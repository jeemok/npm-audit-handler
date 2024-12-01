/* eslint-disable quote-props */
import get from 'lodash.get';
import { table, TableUserConfig } from 'table';
import type {
  SecurityReportHeader,
  ExceptionReportHeader,
  ProcessedResult,
  JsonOutput,
  SecurityReportKey,
  ExceptionReportKey,
} from 'src/types';

const SECURITY_REPORT_HEADER: SecurityReportHeader[] = ['ID', 'Module', 'Title', 'Paths', 'Severity', 'URL', 'Ex.'];
const EXCEPTION_REPORT_HEADER: ExceptionReportHeader[] = ['ID', 'Status', 'Expiry', 'Notes'];

const SECURITY_REPORT_HEADER_TO_OBJECT_KEY_MAP: Record<SecurityReportHeader, SecurityReportKey> = {
  ID: 'id',
  Module: 'module',
  Title: 'title',
  Paths: 'paths',
  Severity: 'severity',
  URL: 'url',
  'Ex.': 'isExcepted',
};

const EXCEPTION_REPORT_HEADER_TO_OBJECT_KEY_MAP: Record<ExceptionReportHeader, ExceptionReportKey> = {
  ID: 'id',
  Status: 'status',
  Expiry: 'expiry',
  Notes: 'notes',
};

const SECURITY_REPORT_KEYS: SecurityReportKey[] = SECURITY_REPORT_HEADER.map((header) => SECURITY_REPORT_HEADER_TO_OBJECT_KEY_MAP[header]);
const EXCEPTION_REPORT_KEYS: ExceptionReportKey[] = EXCEPTION_REPORT_HEADER.map(
  (header) => EXCEPTION_REPORT_HEADER_TO_OBJECT_KEY_MAP[header],
);

// TODO: Add unit tests
/**
 * Get the column width size for the table
 * @param {Array} tableData     Table data (Array of array)
 * @param {Number} columnIndex  Target column index
 * @param {Number} maxWidth     Maximum width
 * @param {Number} minWidth     Minimum width
 * @return {Number}             width
 */
export function getColumnWidth(tableData: string[][], columnIndex: number, maxWidth = 50, minWidth = 15): number {
  // Find the maximum length in the column
  const contentLength = tableData.reduce(
    (max, cur) => {
      let content = JSON.stringify(get(cur, columnIndex, ''));
      // Remove the color codes
      content = content.replace(/\\x1b\[\d{1,2}m/g, '');
      content = content.replace(/\\u001b\[\d{1,2}m/g, '');
      content = content.replace(/"/g, '');
      // Keep whichever number that is bigger
      return content.length > max ? content.length : max;
    },
    // Start with minimum width (also auto handling empty column case)
    minWidth,
  );
  // Return the content length up to a maximum point
  return Math.min(contentLength, maxWidth);
}

/**
 * Print the security report in a table format
 * @param  {Array} data               Array of arrays
 * @return {undefined}                Returns void
 * @param  {Array} columnsToInclude   List of columns to include in audit results
 */
export function printSecurityReport(data: string[][], columnsToInclude: string[]): void {
  const configs: TableUserConfig = {
    singleLine: true,
    header: {
      alignment: 'center',
      content: '=== npm audit security report ===\n',
    },
    columns: {
      // "Title" column index
      2: {
        width: getColumnWidth(data, 2),
        wrapWord: true,
      },
      // "Paths" column index
      3: {
        width: getColumnWidth(data, 3),
        wrapWord: true,
      },
    },
  };
  const headers = columnsToInclude.length ? SECURITY_REPORT_HEADER.filter((h) => columnsToInclude.includes(h)) : SECURITY_REPORT_HEADER;

  console.info(table([headers, ...data], configs));
}

/**
 * Print the exception report in a table format
 * @param  {Array} exceptionsReport   Array of arrays
 * @return {undefined}                Returns void
 */
export function printExceptionReport(exceptionsReport: string[][]): void {
  const configs: TableUserConfig = {
    singleLine: true,
    header: {
      alignment: 'center',
      content: '=== list of exceptions ===\n',
    },
  };

  console.info(table([EXCEPTION_REPORT_HEADER, ...exceptionsReport], configs));
}

/**
 * Print the JSON output
 * @param  {Object} result           The processed result
 * @param  {Array} exceptionsReport  The exceptions report
 * @return {undefined}               Returns void
 */
export function printJsonOutput(result: ProcessedResult, exceptionsReport: string[][]): void {
  const jsonOutput: JsonOutput = {
    failed: result.failed ?? false,
    unhandledVulnerabilityIds: result.unhandledIds.filter(Boolean),
    vulnerabilitiesReport: convertReportTuplesToObjects(result.report, SECURITY_REPORT_KEYS),
    exceptionsReport: convertReportTuplesToObjects(exceptionsReport, EXCEPTION_REPORT_KEYS),
    unusedExceptionIds: result.unusedExceptionIds.filter(Boolean),
  };

  console.info(JSON.stringify(jsonOutput, null, 2));
}

/**
 * Convert a given report tuple to an object with the given headers
 * @param {Array} report  Report where each row is a tuple
 * @param {Array} elementKeyNames Array of object key names to use for each tuple element
 * @return {Array}        Report where each row is an object
 */
function convertReportTuplesToObjects<THeader extends string>(report: string[][], elementKeyNames: THeader[]): Record<THeader, string>[] {
  return report.map((rowTuple) =>
    rowTuple.reduce((rowObj, colValue, i) => {
      const header = elementKeyNames[i];
      rowObj[header] = colValue;
      return rowObj;
    }, {} as Record<string, string>),
  );
}
