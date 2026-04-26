import type { JsonValue } from '../../shared/types';
import { stableStringify } from './json';

export type DynamicColumnKind =
  | 'payload'
  | 'public'
  | 'encrypted';

const KIND_PREFIX: Record<DynamicColumnKind, string> = {
  payload: 'payload',
  public: 'public',
  encrypted: 'encrypted',
};

const QUESTION_COLUMN_NAMES: Record<string, string> = {
  HMaster: '负责人 / 校长姓名',
  abuserInfo: '已知施暴者/教官基本信息与描述',
  abuser_info: '已知施暴者/教官基本信息与描述',
  addr: '机构地址',
  agentRelationship: '与受害者的关系',
  agent_relationship: '与受害者的关系',
  birthDate: '您的出生日期',
  birth_date: '您的出生日期',
  birthDay: '出生日期（日）',
  birthMonth: '出生日期（月）',
  birthYear: '出生年份',
  birth_year: '出生年份',
  city: '机构所在城市',
  cityCode: '机构所在城市代码',
  city_code: '机构所在城市代码',
  clientIpHash: '客户端 IP 哈希',
  contact: '机构联络方式',
  contactInformation: '机构联络方式',
  contact_information: '机构联络方式',
  correctionContent: '更正内容',
  correction_content: '更正内容',
  county: '机构所在县区',
  countyCode: '机构所在县区代码',
  county_code: '机构所在县区代码',
  dateEnd: '离开日期',
  dateStart: '首次被送入日期',
  date_end: '离开日期',
  date_start: '首次被送入日期',
  else: '其它补充',
  experience: '个人在校经历描述',
  exitMethod: '离开机构的方式',
  exit_method: '离开机构的方式',
  exit_method_other: '离开机构的方式（其他）',
  form_variant: '表单版本',
  headmasterName: '负责人 / 校长姓名',
  headmaster_name: '负责人 / 校长姓名',
  identity: '请问您是以什么身份填写本表单',
  inputType: '请问您是以什么身份填写本表单',
  lang: '语言',
  lat: '纬度',
  latitude: '纬度',
  legalAidStatus: '是否曾对此经历进行举报或寻求法律援助',
  legal_aid_other: '是否曾对此经历进行举报或寻求法律援助（其他）',
  legal_aid_status: '是否曾对此经历进行举报或寻求法律援助',
  lng: '经度',
  longitude: '经度',
  name: '机构名称',
  other: '其它补充',
  parentMotivations: '家长选择矫正机构的原因/动机',
  parent_motivation_other: '家长选择矫正机构的原因/动机（其他）',
  parent_motivations: '家长选择矫正机构的原因/动机',
  preInstitutionCity: '进入机构前所在城市',
  preInstitutionCityCode: '进入机构前所在城市代码',
  preInstitutionProvince: '进入机构前所在省份',
  preInstitutionProvinceCode: '进入机构前所在省份代码',
  pre_institution_city_code: '进入机构前所在城市代码',
  pre_institution_province_code: '进入机构前所在省份代码',
  province: '机构所在省份',
  provinceCode: '机构所在省份代码',
  province_code: '机构所在省份代码',
  prov: '机构所在省份',
  recordKind: '记录类型',
  scandal: '机构丑闻及暴力行为详细描述',
  schoolAddress: '机构地址',
  schoolAwarenessBeforeEntry: '在你进去之前是否听说过这种学校或任何关于这种学校的新闻',
  schoolCoordinates: '机构经纬度',
  schoolName: '机构名称',
  school_address: '机构地址',
  school_awareness_before_entry: '在你进去之前是否听说过这种学校或任何关于这种学校的新闻',
  school_coordinates: '机构经纬度',
  school_name: '机构名称',
  sex: '受害者性别',
  sex_other: '受害者性别（其他）',
  sex_other_type: '受害者性别（其他类型）',
  source: '数据来源',
  sourcePath: '提交路径',
  standaloneEnhancements: '独立表单增强模式',
  submittedAt: '提交时间',
  submittedFields: '原始提交字段',
  userAgent: '浏览器 User-Agent',
  violenceCategories: '机构丑闻及暴力行为',
  violence_categories: '机构丑闻及暴力行为',
  violence_category_other: '机构丑闻及暴力行为（其他）',
};

type TableInfoRow = {
  name: string;
};

function hashFieldName(value: string): string {
  let hash = 0x811c9dc5;

  for (const character of value) {
    hash ^= character.codePointAt(0) ?? 0;
    hash = Math.imul(hash, 0x01000193);
  }

  return (hash >>> 0).toString(36);
}

function normalizeFieldName(
  fieldName: string,
): string {
  const normalized = fieldName
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .replace(/_+/g, '_');

  const safeName = normalized || 'field';
  const prefixed = /^[0-9]/.test(safeName)
    ? `f_${safeName}`
    : safeName;

  return prefixed.slice(0, 24);
}

function quoteIdentifier(
  identifier: string,
): string {
  return `"${identifier.replaceAll('"', '""')}"`;
}

function sanitizeQuestionColumnName(value: string): string {
  const normalized = value
    .normalize('NFKC')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  return normalized || '字段';
}

function dynamicColumnName(
  kind: DynamicColumnKind,
  fieldName: string,
): string {
  const mappedQuestion = QUESTION_COLUMN_NAMES[fieldName];
  if (mappedQuestion) {
    return `${KIND_PREFIX[kind]}_${sanitizeQuestionColumnName(mappedQuestion)}`;
  }

  if (/[\p{Script=Han}？?]/u.test(fieldName)) {
    return `${KIND_PREFIX[kind]}_${sanitizeQuestionColumnName(fieldName)}`;
  }

  const baseName = normalizeFieldName(fieldName);
  const hash = hashFieldName(fieldName).slice(0, 6);
  return `${KIND_PREFIX[kind]}_字段_${baseName}_${hash}`;
}

export async function listTableColumns(
  db: D1Database,
  tableName: string,
): Promise<Set<string>> {
  const result = await db
    .prepare(`PRAGMA table_info(${quoteIdentifier(tableName)})`)
    .all<TableInfoRow>();

  return new Set(
    (result.results ?? []).map((row) => row.name),
  );
}

export async function ensureDynamicColumns(
  db: D1Database,
  tableName: string,
  kind: DynamicColumnKind,
  fieldNames: Iterable<string>,
): Promise<Map<string, string>> {
  const uniqueFieldNames = Array.from(
    new Set(
      Array.from(fieldNames)
        .map((fieldName) => fieldName.trim())
        .filter(Boolean),
    ),
  ).sort((left, right) => left.localeCompare(right));

  const mappings = new Map<string, string>();
  if (!uniqueFieldNames.length) {
    return mappings;
  }

  const existingColumns = await listTableColumns(db, tableName);

  for (const fieldName of uniqueFieldNames) {
    const columnName = dynamicColumnName(kind, fieldName);
    mappings.set(fieldName, columnName);

    if (existingColumns.has(columnName)) {
      continue;
    }

    try {
      await db
        .prepare(
          `
            ALTER TABLE ${quoteIdentifier(tableName)}
            ADD COLUMN ${quoteIdentifier(columnName)} TEXT
          `,
        )
        .run();
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : String(error);

      if (!/duplicate column name/i.test(message)) {
        throw error;
      }
    }

    existingColumns.add(columnName);
  }

  return mappings;
}

export function serializeDynamicColumnValue(
  value: JsonValue,
): string | null {
  if (value === null) {
    return null;
  }

  if (typeof value === 'string') {
    return value;
  }

  if (
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return String(value);
  }

  return stableStringify(value);
}

export function extractDynamicColumns(
  row: Record<string, unknown>,
  kind: DynamicColumnKind,
  fieldNames: Iterable<string>,
): Record<string, string | null> {
  const values: Record<string, string | null> = {};

  Array.from(
    new Set(Array.from(fieldNames).filter(Boolean)),
  )
    .sort((left, right) => left.localeCompare(right))
    .forEach((fieldName) => {
      const columnName = dynamicColumnName(kind, fieldName);
      const value = row[columnName];

      if (value === undefined) {
        return;
      }

      values[fieldName] =
        value === null ? null : String(value);
    });

  return values;
}
