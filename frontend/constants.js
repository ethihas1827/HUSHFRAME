/**
 * @file constants.js
 * @brief Centralized terminology guide and UI string constants for Hushframe.
 *
 * Enforces consistent, professional, calm, sentence-case terminology across the application.
 */

const Terminology = Object.freeze({
  APP_NAME: 'Hushframe',
  TAGLINE: 'Protect sensitive files within ordinary images',

  // Core Actions
  ACTION_PROTECT_FILE: 'Protect a file',
  ACTION_RECOVER_FILE: 'Recover a file',
  BTN_PROTECT_FILE: 'Protect file',
  BTN_RECOVER_FILE: 'Recover file',
  BTN_PROTECT_ANOTHER: 'Protect another file',
  BTN_RECOVER_ANOTHER: 'Recover another file',
  BTN_RETURN_HOME: 'Return to home',
  BTN_DOWNLOAD_PROTECTED: 'Download protected image',
  BTN_DOWNLOAD_RECOVERED: 'Download recovered file',
  BTN_DOWNLOAD_CLEAN: 'Download clean image',
  BTN_REMOVE_LOCATION: 'Remove location data',
  BTN_REMOVE_METADATA: 'Remove all metadata',

  // Flow Step Labels
  STEP_SELECT_COVER: 'Select a cover image',
  STEP_CHOOSE_CONTENT: 'Choose the content to protect',
  STEP_PASSWORD: 'Add password protection',
  STEP_SUMMARY: 'Review summary',
  STEP_SELECT_PROTECTED: 'Select a protected image',
  STEP_ENTER_PASSWORD: 'Enter password',

  // Content Types
  CONTENT_TEXT: 'Text message',
  CONTENT_FILE: 'File',

  // Status & Success Messages
  MSG_PROTECTED_READY: 'Your protected image is ready.',
  MSG_RECOVERED_SUCCESS: 'File recovered successfully.',
  MSG_LOCATION_FOUND: 'Location information found',
  MSG_LOCATION_WARNING: 'This image may reveal where it was taken.',
  MSG_NO_LOCATION: 'No location information was found in this image.',
  MSG_LOCATION_REMOVED: 'Location data removed. Your cleaned image is ready.',

  // Standard Error Messages
  ERR_FILE_TOO_LARGE: 'The selected file exceeds the available capacity of this image. Select a larger cover image or reduce the file size.',
  ERR_WRONG_PASSWORD: 'The password is incorrect, or the protected image has been modified. The file could not be recovered.',
  ERR_MISSING_PASSWORD: 'This image is password protected. Enter the password used when the file was protected.',
  ERR_INVALID_IMAGE: 'The selected file is not a supported image format. Select a valid PNG, JPEG, BMP, WEBP, or GIF image.',
  ERR_OUTPUT_ERROR: 'The protected image could not be saved. Select a folder where you have permission to save files.',
  ERR_IMAGE_MODIFIED: 'This image may have been resized, recompressed, or edited. The embedded data may no longer be recoverable.',
  ERR_SERVER_CONNECTION: 'Failed to communicate with the local server. Ensure the Hushframe server is running.',

  // Protection Labels
  LABEL_PASSWORD_PROTECTED: 'Password protected',
  LABEL_STANDARD_PROTECTION: 'Standard protection',

  // Technical Details Constants
  TECH_ENVELOPE_ENCRYPTED: 'CMC2 Encrypted',
  TECH_ENVELOPE_STANDARD: 'CMC1 Standard',
  TECH_KDF: 'Argon2id',
  TECH_ENCRYPTION: 'AES-256-GCM',
  TECH_INTEGRITY: 'Verified'
});

