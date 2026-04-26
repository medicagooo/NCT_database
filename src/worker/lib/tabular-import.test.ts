import { describe, expect, it } from 'vitest';
import { parseTabularImport } from './tabular-import';

describe('parseTabularImport', () => {
  it('parses pasted Excel tables, maps known columns, and drops duplicate rows', async () => {
    const result = await parseTabularImport(
      [
        '机构名称\t机构地址\t机构所在省份\t机构经纬度\t未知列',
        '测试机构\t测试地址\t广东\t23.129110, 113.264385\t忽略我',
        '测试机构\t测试地址\t广东\t23.129110, 113.264385\t重复行',
      ].join('\n'),
      { dataSourceType: 'batch_query', source: 'manual-test' },
    );

    expect(result.inputRowCount).toBe(2);
    expect(result.parsedRowCount).toBe(1);
    expect(result.duplicateRowCount).toBe(1);
    expect(result.unknownColumns).toEqual(['未知列']);
    expect(result.records[0]).toMatchObject({
      dataSourceType: 'batch_query',
      recordKey: expect.stringMatching(/^admin-import:[a-f0-9]{32}$/),
      source: 'manual-test',
      payload: {
        addr: '测试地址',
        lat: 23.12911,
        latitude: 23.12911,
        lng: 113.264385,
        longitude: 113.264385,
        name: '测试机构',
        prov: '广东',
        province: '广东',
        schoolAddress: '测试地址',
        schoolCoordinates: '23.129110, 113.264385',
        schoolName: '测试机构',
      },
    });
  });

  it('parses markdown tables and preserves explicit record keys', async () => {
    const result = await parseTabularImport(`
| recordKey | 机构名称 | 负责人 / 校长姓名 | 其它补充 |
| --- | --- | --- | --- |
| school-1 | 示例机构 | 张三 | 备注 |
`);

    expect(result.unknownColumns).toEqual([]);
    expect(result.records).toHaveLength(1);
    expect(result.records[0]).toMatchObject({
      dataSourceType: 'batch_query',
      recordKey: 'school-1',
      payload: {
        HMaster: '张三',
        else: '备注',
        headmasterName: '张三',
        name: '示例机构',
        other: '备注',
        recordKey: 'school-1',
        schoolName: '示例机构',
      },
    });
  });

  it('recognizes Traditional Chinese form headers', async () => {
    const result = await parseTabularImport(
      [
        '機構名稱\t機構地址\t機構所在省份\t機構經緯度\t機構醜聞及暴力行為',
        '繁體機構\t繁體地址\t廣東\t23.1, 113.2\t體罰；辱罵',
      ].join('\n'),
    );

    expect(result.unknownColumns).toEqual([]);
    expect(result.records[0]?.payload).toMatchObject({
      addr: '繁體地址',
      lat: 23.1,
      lng: 113.2,
      name: '繁體機構',
      province: '廣東',
      schoolCoordinates: '23.1, 113.2',
      scandal: ['體罰', '辱罵'],
      violenceCategories: ['體罰', '辱罵'],
    });
  });

  it('marks questionnaire imports separately from batch query imports', async () => {
    const result = await parseTabularImport(
      [
        '记录编号\t机构名称\t数据来源类型',
        'school-2\t问卷机构\t问卷数据',
      ].join('\n'),
      { dataSourceType: 'batch_query', source: 'manual-test' },
    );

    expect(result.records[0]).toMatchObject({
      dataSourceType: 'questionnaire',
      recordKey: 'school-2',
      source: 'manual-test',
    });
    expect(result.previewRecords[0]).toMatchObject({
      dataSourceType: 'questionnaire',
    });
  });
});
