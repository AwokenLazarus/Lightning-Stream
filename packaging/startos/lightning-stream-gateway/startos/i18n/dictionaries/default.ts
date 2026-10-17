export const DEFAULT_LANG = 'en_US'

const dict = {
  'Anyone with the new setup code can choose the password. The gateway, its config and its macaroons are not affected.': 0,
  'Forget the setup page password. The service restarts and the UI asks for a new setup code.': 1,
  'Gateway for buyers': 2,
  'Listening': 3,
  'Not listening yet': 4,
  'Once the service runs, get the setup code and choose the setup page password': 5,
  'Open the setup page, enter this code, then choose its password (at least 10 characters).': 6,
  'Reset the setup page password': 7,
  'Run Setup page code once the service is running again.': 8,
  'Set the service you sell, its price, the address buyers use and the macaroons': 9,
  'Setup code': 10,
  'Setup page': 11,
  'Setup page code': 12,
  'Setup page password reset': 13,
  'Taking stream tickets': 14,
  'The gateway answers but is not ready: see the setup page': 15,
  'The one-time code the setup page asks for before you choose its password': 16,
  'The setup page password is already set. To choose a new one, run Reset the setup page password.': 17,
  'Waiting for the setup page: set the service, the price and the macaroons': 18,
  'Where buyers reach the service you sell; add a public domain to it to sell outside your LAN': 19,
} as const

/**
 * Plumbing. DO NOT EDIT.
 */
export type I18nKey = keyof typeof dict
export type LangDict = Record<(typeof dict)[I18nKey], string>
export default dict
