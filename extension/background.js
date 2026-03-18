/*
  background.js — Service Worker
  ================================
  Handles extension install events and relays messages between
  the popup and content scripts when needed.
*/

chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === 'install') {
    console.log('[PasswordManager] Extension installed and ready.');
  }
});

// Relay GET_TOKEN requests from content scripts back to storage
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'GET_TOKEN') {
    chrome.storage.local.get('ext_token', d => sendResponse({ token: d.ext_token || null }));
    return true;  // keep async channel open
  }
});
