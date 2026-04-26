import type { DataSourceType, IngestRecordInput, JsonObject, JsonValue } from '../../shared/types';
import { sha256 } from './crypto';
import { stableStringify } from './json';

type ColumnHandler = {
  keys?: string[];
  apply?: (payload: JsonObject, value: string) => void;
  kind?: 'data-source-type' | 'payload' | 'record-key' | 'source';
};

export type ParsedImportRecord = {
  dataSourceType: DataSourceType;
  payload: JsonObject;
  recordKey: string;
  rowNumber: number;
  source: string;
};

export type ParsedTabularImport = {
  duplicateRowCount: number;
  inputRowCount: number;
  parsedRowCount: number;
  records: IngestRecordInput[];
  previewRecords: ParsedImportRecord[];
  recognizedColumns: Array<{
    columns: string[];
    name: string;
  }>;
  skippedEmptyRowCount: number;
  unknownColumns: string[];
};

const defaultImportSource = 'admin-tabular-import';
const defaultImportDataSourceType: DataSourceType = 'batch_query';
const maxImportSourceLength = 120;
const maxCellTextLength = 8000;

function normalizeHeader(value: string): string {
  return value
    .trim()
    .replace(/^#+\s*/, '')
    .replace(/\*\*/g, '')
    .replace(/[：:]\s*$/g, '')
    .replace(/\s+/g, ' ')
    .toLowerCase();
}

function compactHeader(value: string): string {
  return normalizeHeader(value)
    .replace(/[()（）[\]【】]/g, '')
    .replace(/[\s/_-]+/g, '')
    .replace(/[?？]/g, '');
}

function normalizeCell(value: string): string {
  return value.trim().slice(0, maxCellTextLength);
}

function normalizeDataSourceType(
  value: string,
  fallback: DataSourceType,
): DataSourceType {
  const normalized = normalizeHeader(value).replace(/[\s_-]+/g, '');

  if (
    normalized === 'questionnaire'
    || normalized === '问卷'
    || normalized === '問卷'
    || normalized === '问卷数据'
    || normalized === '問卷資料'
    || normalized === '表单'
    || normalized === '表單'
  ) {
    return 'questionnaire';
  }

  if (
    normalized === 'batchquery'
    || normalized === 'batch'
    || normalized === '批量查询'
    || normalized === '批量查詢'
    || normalized === '批量查询数据'
    || normalized === '批量查詢資料'
  ) {
    return 'batch_query';
  }

  return fallback;
}

function parseNumber(value: string): number | null {
  const normalized = normalizeCell(value);
  if (!normalized) {
    return null;
  }

  const parsed = Number(normalized);
  return Number.isFinite(parsed) ? parsed : null;
}

function setPayloadValue(
  payload: JsonObject,
  key: string,
  value: JsonValue,
) {
  if (payload[key] === undefined) {
    payload[key] = value;
  }
}

function setTextKeys(
  payload: JsonObject,
  keys: string[],
  value: string,
) {
  const text = normalizeCell(value);
  if (!text) {
    return;
  }

  keys.forEach((key) => setPayloadValue(payload, key, text));
}

function setNumberKeys(
  payload: JsonObject,
  keys: string[],
  value: string,
) {
  const parsed = parseNumber(value);
  if (parsed === null) {
    setTextKeys(payload, keys, value);
    return;
  }

  keys.forEach((key) => setPayloadValue(payload, key, parsed));
}

function setDelimitedListKeys(
  payload: JsonObject,
  keys: string[],
  value: string,
) {
  const text = normalizeCell(value);
  if (!text) {
    return;
  }

  const items = text
    .split(/[;；,，\n]/)
    .map((item) => item.trim())
    .filter(Boolean);
  const valueToStore = items.length > 1 ? items : text;
  keys.forEach((key) => setPayloadValue(payload, key, valueToStore));
}

function setCoordinateValue(payload: JsonObject, value: string) {
  const text = normalizeCell(value);
  if (!text) {
    return;
  }

  setPayloadValue(payload, 'schoolCoordinates', text);
  const match =
    /^([+-]?(?:\d+(?:\.\d+)?|\.\d+))\s*[,，]\s*([+-]?(?:\d+(?:\.\d+)?|\.\d+))$/.exec(
      text,
    );
  if (!match) {
    return;
  }

  const lat = Number(match[1]);
  const lng = Number(match[2]);
  if (
    Number.isFinite(lat)
    && Number.isFinite(lng)
    && lat >= -90
    && lat <= 90
    && lng >= -180
    && lng <= 180
  ) {
    setPayloadValue(payload, 'lat', lat);
    setPayloadValue(payload, 'latitude', lat);
    setPayloadValue(payload, 'lng', lng);
    setPayloadValue(payload, 'longitude', lng);
  }
}

function textHandler(...keys: string[]): ColumnHandler {
  return {
    keys,
    apply: (payload, value) => setTextKeys(payload, keys, value),
  };
}

function numberHandler(...keys: string[]): ColumnHandler {
  return {
    keys,
    apply: (payload, value) => setNumberKeys(payload, keys, value),
  };
}

function listHandler(...keys: string[]): ColumnHandler {
  return {
    keys,
    apply: (payload, value) => setDelimitedListKeys(payload, keys, value),
  };
}

const columnHandlers: Record<string, ColumnHandler> = {
  recordkey: { kind: 'record-key' },
  record_key: { kind: 'record-key' },
  记录id: { kind: 'record-key' },
  记录编号: { kind: 'record-key' },
  source: { kind: 'source' },
  来源: { kind: 'source' },
  数据来源: { kind: 'source' },
  datasource_type: { kind: 'data-source-type' },
  data_source_type: { kind: 'data-source-type' },
  数据来源类型: { kind: 'data-source-type' },
  数据类型: { kind: 'data-source-type' },
  來源類型: { kind: 'data-source-type' },
  資料類型: { kind: 'data-source-type' },
  机构名称: textHandler('name', 'schoolName'),
  機構名稱: textHandler('name', 'schoolName'),
  机构名: textHandler('name', 'schoolName'),
  機構名: textHandler('name', 'schoolName'),
  学校名称: textHandler('name', 'schoolName'),
  學校名稱: textHandler('name', 'schoolName'),
  学校名: textHandler('name', 'schoolName'),
  學校名: textHandler('name', 'schoolName'),
  名称: textHandler('name', 'schoolName'),
  名稱: textHandler('name', 'schoolName'),
  name: textHandler('name', 'schoolName'),
  schoolname: textHandler('name', 'schoolName'),
  school_name: textHandler('name', 'schoolName'),
  机构地址: textHandler('addr', 'schoolAddress'),
  機構地址: textHandler('addr', 'schoolAddress'),
  学校地址: textHandler('addr', 'schoolAddress'),
  學校地址: textHandler('addr', 'schoolAddress'),
  地址: textHandler('addr', 'schoolAddress'),
  addr: textHandler('addr', 'schoolAddress'),
  address: textHandler('addr', 'schoolAddress'),
  schooladdress: textHandler('addr', 'schoolAddress'),
  school_address: textHandler('addr', 'schoolAddress'),
  机构所在省份: textHandler('province', 'prov'),
  機構所在省份: textHandler('province', 'prov'),
  所在省份: textHandler('province', 'prov'),
  省份: textHandler('province', 'prov'),
  province: textHandler('province', 'prov'),
  prov: textHandler('province', 'prov'),
  机构所在城市区县: textHandler('city'),
  機構所在城市區縣: textHandler('city'),
  机构所在城市: textHandler('city'),
  機構所在城市: textHandler('city'),
  所在城市: textHandler('city'),
  城市: textHandler('city'),
  city: textHandler('city'),
  机构所在县区: textHandler('county'),
  機構所在縣區: textHandler('county'),
  机构所在区县: textHandler('county'),
  機構所在區縣: textHandler('county'),
  县区: textHandler('county'),
  縣區: textHandler('county'),
  区县: textHandler('county'),
  區縣: textHandler('county'),
  county: textHandler('county'),
  district: textHandler('county'),
  机构经纬度: { keys: ['schoolCoordinates', 'lat', 'lng'], apply: setCoordinateValue },
  機構經緯度: { keys: ['schoolCoordinates', 'lat', 'lng'], apply: setCoordinateValue },
  经纬度: { keys: ['schoolCoordinates', 'lat', 'lng'], apply: setCoordinateValue },
  經緯度: { keys: ['schoolCoordinates', 'lat', 'lng'], apply: setCoordinateValue },
  坐标: { keys: ['schoolCoordinates', 'lat', 'lng'], apply: setCoordinateValue },
  坐標: { keys: ['schoolCoordinates', 'lat', 'lng'], apply: setCoordinateValue },
  coordinates: { keys: ['schoolCoordinates', 'lat', 'lng'], apply: setCoordinateValue },
  schoolcoordinates: { keys: ['schoolCoordinates', 'lat', 'lng'], apply: setCoordinateValue },
  school_coordinates: { keys: ['schoolCoordinates', 'lat', 'lng'], apply: setCoordinateValue },
  纬度: numberHandler('lat', 'latitude'),
  latitude: numberHandler('lat', 'latitude'),
  lat: numberHandler('lat', 'latitude'),
  经度: numberHandler('lng', 'longitude'),
  longitude: numberHandler('lng', 'longitude'),
  lng: numberHandler('lng', 'longitude'),
  个人在校经历描述: textHandler('experience'),
  個人在校經歷描述: textHandler('experience'),
  在校经历: textHandler('experience'),
  在校經歷: textHandler('experience'),
  经历: textHandler('experience'),
  經歷: textHandler('experience'),
  experience: textHandler('experience'),
  机构丑闻及暴力行为: listHandler('scandal', 'violenceCategories'),
  機構醜聞及暴力行為: listHandler('scandal', 'violenceCategories'),
  丑闻及暴力行为: listHandler('scandal', 'violenceCategories'),
  醜聞及暴力行為: listHandler('scandal', 'violenceCategories'),
  暴力行为: listHandler('scandal', 'violenceCategories'),
  暴力行為: listHandler('scandal', 'violenceCategories'),
  violencecategories: listHandler('violenceCategories'),
  violence_categories: listHandler('violenceCategories'),
  丑闻及暴力行为详细描述: textHandler('scandal'),
  醜聞及暴力行為詳細描述: textHandler('scandal'),
  详细描述: textHandler('scandal'),
  詳細描述: textHandler('scandal'),
  scandal: textHandler('scandal'),
  其它补充: textHandler('else', 'other'),
  其他补充: textHandler('else', 'other'),
  补充: textHandler('else', 'other'),
  备注: textHandler('else', 'other'),
  else: textHandler('else', 'other'),
  other: textHandler('else', 'other'),
  机构联络方式: textHandler('contact', 'contactInformation'),
  機構聯絡方式: textHandler('contact', 'contactInformation'),
  联系方式: textHandler('contact', 'contactInformation'),
  聯絡方式: textHandler('contact', 'contactInformation'),
  联系电话: textHandler('contact', 'contactInformation'),
  聯絡電話: textHandler('contact', 'contactInformation'),
  contact: textHandler('contact', 'contactInformation'),
  contactinformation: textHandler('contact', 'contactInformation'),
  contact_information: textHandler('contact', 'contactInformation'),
  负责人校长姓名: textHandler('HMaster', 'headmasterName'),
  負責人校長姓名: textHandler('HMaster', 'headmasterName'),
  负责人: textHandler('HMaster', 'headmasterName'),
  負責人: textHandler('HMaster', 'headmasterName'),
  校长: textHandler('HMaster', 'headmasterName'),
  校長: textHandler('HMaster', 'headmasterName'),
  校长姓名: textHandler('HMaster', 'headmasterName'),
  校長姓名: textHandler('HMaster', 'headmasterName'),
  hmaster: textHandler('HMaster', 'headmasterName'),
  headmastername: textHandler('HMaster', 'headmasterName'),
  headmaster_name: textHandler('HMaster', 'headmasterName'),
  请问您是以什么身份填写本表单: textHandler('inputType'),
  请问您是以什麼身份填寫本表單: textHandler('inputType'),
  填写身份: textHandler('inputType'),
  填寫身份: textHandler('inputType'),
  身份: textHandler('inputType'),
  inputtype: textHandler('inputType'),
  受害者性别: textHandler('sex'),
  受害者性別: textHandler('sex'),
  性别: textHandler('sex'),
  性別: textHandler('sex'),
  sex: textHandler('sex'),
  您的出生日期: textHandler('birthDate'),
  出生日期: textHandler('birthDate'),
  出生年份: textHandler('birthYear'),
  birthdate: textHandler('birthDate'),
  birth_date: textHandler('birthDate'),
  birthyear: textHandler('birthYear'),
  birth_year: textHandler('birthYear'),
  进入机构前所在省份: textHandler('preInstitutionProvince'),
  進入機構前所在省份: textHandler('preInstitutionProvince'),
  进入机构前所在城市: textHandler('preInstitutionCity'),
  進入機構前所在城市: textHandler('preInstitutionCity'),
  preinstitutionprovince: textHandler('preInstitutionProvince'),
  preinstitutioncity: textHandler('preInstitutionCity'),
  首次被送入日期: textHandler('dateStart'),
  进入日期: textHandler('dateStart'),
  進入日期: textHandler('dateStart'),
  离开日期: textHandler('dateEnd'),
  離開日期: textHandler('dateEnd'),
  datestart: textHandler('dateStart'),
  date_start: textHandler('dateStart'),
  dateend: textHandler('dateEnd'),
  date_end: textHandler('dateEnd'),
  家长选择矫正机构的原因动机: listHandler('parentMotivations'),
  家長選擇矯正機構的原因動機: listHandler('parentMotivations'),
  parentmotivations: listHandler('parentMotivations'),
  parent_motivations: listHandler('parentMotivations'),
  在你进去之前是否听说过这种学校或任何关于这种学校的新闻: textHandler('schoolAwarenessBeforeEntry'),
  在你進去之前是否聽說過這種學校或任何關於這種學校的新聞: textHandler('schoolAwarenessBeforeEntry'),
  schoolawarenessbeforeentry: textHandler('schoolAwarenessBeforeEntry'),
  是否曾对此经历进行举报或寻求法律援助: textHandler('legalAidStatus'),
  是否曾對此經歷進行舉報或尋求法律援助: textHandler('legalAidStatus'),
  legalaidstatus: textHandler('legalAidStatus'),
  legal_aid_status: textHandler('legalAidStatus'),
  已知施暴者教官基本资讯与描述: textHandler('abuserInfo'),
  已知施暴者教官基本資訊與描述: textHandler('abuserInfo'),
  施暴者信息: textHandler('abuserInfo'),
  施暴者資訊: textHandler('abuserInfo'),
  abuserinfo: textHandler('abuserInfo'),
  abuser_info: textHandler('abuserInfo'),
  与受害者的关系: textHandler('agentRelationship'),
  與受害者的關係: textHandler('agentRelationship'),
  agentrelationship: textHandler('agentRelationship'),
  agent_relationship: textHandler('agentRelationship'),
};

function resolveColumnHandler(header: string): ColumnHandler | null {
  const normalized = normalizeHeader(header);
  return columnHandlers[normalized]
    ?? columnHandlers[compactHeader(header)]
    ?? null;
}

function splitMarkdownRow(line: string): string[] {
  const trimmed = line.trim().replace(/^\|/, '').replace(/\|$/, '');
  const cells: string[] = [];
  let current = '';
  let escaped = false;

  for (const character of trimmed) {
    if (escaped) {
      current += character;
      escaped = false;
      continue;
    }

    if (character === '\\') {
      escaped = true;
      continue;
    }

    if (character === '|') {
      cells.push(current.trim());
      current = '';
      continue;
    }

    current += character;
  }

  cells.push(current.trim());
  return cells;
}

function isMarkdownSeparator(line: string): boolean {
  const cells = splitMarkdownRow(line);
  return cells.length > 0
    && cells.every((cell) => /^:?-{3,}:?$/.test(cell.trim()));
}

function parseCsvLine(line: string): string[] {
  const cells: string[] = [];
  let current = '';
  let quoted = false;

  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (character === '"') {
      if (quoted && line[index + 1] === '"') {
        current += '"';
        index += 1;
        continue;
      }

      quoted = !quoted;
      continue;
    }

    if (character === ',' && !quoted) {
      cells.push(current.trim());
      current = '';
      continue;
    }

    current += character;
  }

  cells.push(current.trim());
  return cells;
}

function parsePastedTable(text: string): string[][] {
  const lines = text
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .split('\n')
    .map((line) => line.trimEnd())
    .filter((line) => line.trim());

  const markdownLines = lines.filter((line) => line.includes('|'));
  if (markdownLines.length >= 2 && markdownLines.some(isMarkdownSeparator)) {
    return markdownLines
      .filter((line) => !isMarkdownSeparator(line))
      .map(splitMarkdownRow);
  }

  if (lines.some((line) => line.includes('\t'))) {
    return lines.map((line) => line.split('\t').map((cell) => cell.trim()));
  }

  return lines.map(parseCsvLine);
}

function buildRecognizedColumns(
  headers: string[],
  handlers: Array<ColumnHandler | null>,
): ParsedTabularImport['recognizedColumns'] {
  return headers.flatMap((header, index) => {
    const handler = handlers[index];
    if (!handler) {
      return [];
    }

    if (handler.kind === 'record-key') {
      return [{ columns: ['recordKey'], name: header }];
    }

    if (handler.kind === 'source') {
      return [{ columns: ['source'], name: header }];
    }

    if (handler.kind === 'data-source-type') {
      return [{ columns: ['dataSourceType'], name: header }];
    }

    return [
      {
        columns: handler.keys ?? [],
        name: header,
      },
    ];
  });
}

function buildPayloadIdentity(payload: JsonObject): JsonObject {
  const candidateKeys = [
    'name',
    'addr',
    'province',
    'city',
    'county',
    'schoolCoordinates',
    'lat',
    'lng',
  ];
  const identity = candidateKeys.reduce<JsonObject>((accumulator, key) => {
    const value = payload[key];
    if (value !== undefined && value !== null && String(value).trim()) {
      accumulator[key] = value;
    }

    return accumulator;
  }, {});

  return Object.keys(identity).length > 0 ? identity : payload;
}

async function buildRecordKey(payload: JsonObject): Promise<string> {
  const digest = await sha256(stableStringify(buildPayloadIdentity(payload)));
  return `admin-import:${digest.slice(0, 32)}`;
}

export async function parseTabularImport(
  text: string,
  options: {
    dataSourceType?: DataSourceType;
    source?: string;
  } = {},
): Promise<ParsedTabularImport> {
  const table = parsePastedTable(text);
  if (table.length === 0) {
    return {
      duplicateRowCount: 0,
      inputRowCount: 0,
      parsedRowCount: 0,
      records: [],
      previewRecords: [],
      recognizedColumns: [],
      skippedEmptyRowCount: 0,
      unknownColumns: [],
    };
  }

  const headers = table[0]!.map((header) => normalizeCell(header));
  const handlers = headers.map(resolveColumnHandler);
  const unknownColumns = Array.from(
    new Set(
      headers.filter((header, index) => header && !handlers[index]),
    ),
  );
  const recognizedColumns = buildRecognizedColumns(headers, handlers);
  const defaultSource = normalizeCell(options.source ?? defaultImportSource)
    || defaultImportSource;
  const limitedDefaultSource = defaultSource.slice(0, maxImportSourceLength);
  const defaultDataSourceType = options.dataSourceType ?? defaultImportDataSourceType;
  const seenRecordKeys = new Set<string>();
  const records: IngestRecordInput[] = [];
  const previewRecords: ParsedImportRecord[] = [];
  let duplicateRowCount = 0;
  let skippedEmptyRowCount = 0;

  for (const [rowIndex, row] of table.slice(1).entries()) {
    const payload: JsonObject = {};
    let dataSourceType = defaultDataSourceType;
    let recordKey = '';
    let source = limitedDefaultSource;

    headers.forEach((_header, columnIndex) => {
      const handler = handlers[columnIndex];
      const value = normalizeCell(row[columnIndex] ?? '');
      if (!handler || !value) {
        return;
      }

      if (handler.kind === 'record-key') {
        recordKey = value;
        setPayloadValue(payload, 'recordKey', value);
        return;
      }

      if (handler.kind === 'source') {
        source = value.slice(0, maxImportSourceLength);
        return;
      }

      if (handler.kind === 'data-source-type') {
        dataSourceType = normalizeDataSourceType(value, defaultDataSourceType);
        return;
      }

      handler.apply?.(payload, value);
    });

    if (Object.keys(payload).length === 0) {
      skippedEmptyRowCount += 1;
      continue;
    }

    const resolvedRecordKey = recordKey || await buildRecordKey(payload);
    if (seenRecordKeys.has(resolvedRecordKey)) {
      duplicateRowCount += 1;
      continue;
    }

    seenRecordKeys.add(resolvedRecordKey);
    records.push({
      dataSourceType,
      payload,
      recordKey: resolvedRecordKey,
      source,
    });
    previewRecords.push({
      dataSourceType,
      payload,
      recordKey: resolvedRecordKey,
      rowNumber: rowIndex + 2,
      source,
    });
  }

  return {
    duplicateRowCount,
    inputRowCount: Math.max(0, table.length - 1),
    parsedRowCount: records.length,
    records,
    previewRecords,
    recognizedColumns,
    skippedEmptyRowCount,
    unknownColumns,
  };
}
