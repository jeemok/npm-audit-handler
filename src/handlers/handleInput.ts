import semver from 'semver';
import { AuditLevel, CommandOptions } from 'src/types';
import { getNpmVersion } from '../utils/npm';
import { readFile } from '../utils/file';
import { getExceptionsIds } from '../utils/vulnerability';

/**
 * Get the `npm audit` flag to audit only production dependencies.
 * @return {String} The flag.
 */
function getProductionOnlyOption() {
  const npmVersion = getNpmVersion();
  if (semver.satisfies(npmVersion, '<=8.13.2')) {
    return '--production';
  } else {
    return '--omit=dev';
  }
}
/**
 * Handle user's input
 * @param  {Object} options     User's command options or flags
 * @param  {Function} fn        The function to handle the inputs
 */
export default function handleInput(
  options: CommandOptions,
  fn: (T1: string, T2: AuditLevel, T3: string[], T4: string[], T5: string[]) => void,
): void {
  // Generate NPM Audit command
  const auditCommand: string = [
    'npm audit',
    // flags
    options.production ? getProductionOnlyOption() : '',
    options.registry ? `--registry=${options.registry}` : '',
  ]
    .filter(Boolean)
    .join(' ');

  // Taking the audit level from the command or environment variable
  const envVar = process.env.NPM_CONFIG_AUDIT_LEVEL as AuditLevel;
  const auditLevel: AuditLevel = options.level || envVar || 'info';

  // Get the exceptions
  const nsprc = readFile('.nsprc');
  const cmdExceptions: string[] = (options.exclude || '')
    .split(',')
    .map((each) => each.trim())
    .filter((each) => each !== '');
  const exceptionIds: string[] = getExceptionsIds(nsprc, cmdExceptions);
  const cmdModuleIgnore: string[] = (options.moduleIgnore || '').split(',');
  const cmdIncludeColumns: string[] = (options.includeColumns || '')
    .split(',')
    .map((each: string) => each.trim())
    .filter((each: string) => !!each);

  fn(auditCommand, auditLevel, exceptionIds, cmdModuleIgnore, cmdIncludeColumns);
}
