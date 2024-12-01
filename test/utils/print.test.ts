import { printSecurityReport, printExceptionReport } from '../../src/utils/print';

import EXCEPTION_TABLE_DATA from '../__mocks__/exception-table-data.json';
import V6_SECURITY_REPORT_TABLE_DATA from '../__mocks__/v6-security-report-table-data.json';
import V7_SECURITY_REPORT_TABLE_DATA from '../__mocks__/v7-security-report-table-data.json';

describe('Print utils', () => {
  it('v6 security report table visual', () => {
    printSecurityReport(V6_SECURITY_REPORT_TABLE_DATA, []);
  });

  it('v7 security report table visual', () => {
    printSecurityReport(V7_SECURITY_REPORT_TABLE_DATA, []);
  });

  it('exception table visual', () => {
    printExceptionReport(EXCEPTION_TABLE_DATA);
  });

  // todo add json output tests
});

export {};
