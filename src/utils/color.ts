import { Severity, Color, ColorCode } from 'src/types';

const RESET = '\x1b[0m' as const;
const COLORS = <const>{
  reset: {
    fg: '\x1b[0m',
    bg: '\x1b[0m',
  },
  black: {
    fg: '\x1b[30m',
    bg: '\x1b[40m',
  },
  red: {
    fg: '\x1b[31m',
    bg: '\x1b[41m',
  },
  green: {
    fg: '\x1b[32m',
    bg: '\x1b[42m',
  },
  yellow: {
    fg: '\x1b[33m',
    bg: '\x1b[43m',
  },
  blue: {
    fg: '\x1b[34m',
    bg: '\x1b[44m',
  },
  magenta: {
    fg: '\x1b[35m',
    bg: '\x1b[45m',
  },
  cyan: {
    fg: '\x1b[36m',
    bg: '\x1b[46m',
  },
  white: {
    fg: '\x1b[37m',
    bg: '\x1b[47m',
  },
};

/**
 * Color a console message's foreground and background
 * @param  {String} message     Message
 * @param  {String} fgColor     Foreground color
 * @param  {String} bgColor     Background color
 * @return {String}             Message
 */
export function color(message: string, fgColor?: Color, bgColor?: Color): string {
  if ('NO_COLOR' in process.env) {
    return message;
  }

  return [
    <ColorCode>(fgColor ? COLORS[fgColor].fg : ''),
    <ColorCode>(bgColor ? COLORS[bgColor].bg : ''),
    message,
    <ColorCode>RESET, // Reset the color at the end
  ].join('');
}

/**
 * Get background color based on severity
 * @param {String} severity           Vulnerability's severity
 * @return {(String | undefined)}     Background color or undefined
 */
export function getSeverityBgColor(severity: Severity): 'red' | undefined {
  switch (severity) {
    case 'info':
      return undefined;
    case 'low':
      return undefined;
    case 'moderate':
      return undefined;
    case 'high':
      return 'red';
    case 'critical':
      return 'red';
    default: {
      const exhaustiveCheck: never = severity;
      return exhaustiveCheck;
    }
  }
}
