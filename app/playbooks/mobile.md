# Surface: Mobile (React Native / Expo)
Checklist
- Secrets shipped in the app: keys in app.json / app.config.js / eas.json / amplify/ team-provider-info.json / aws-exports.js / constants; anything in the JS bundle is public.
- Backend trust: Amplify/Appsync/API Gateway auth modes (API key vs Cognito vs IAM), unauthenticated GraphQL/REST access, Lambda functions under amplify/backend/function/*/src and their own package.json.
- Deep links and universal links: scheme handling, parameters flowing into navigation, auth or purchases without validation.
- Storage: tokens or PII in AsyncStorage/MMKV vs SecureStore/Keychain; logging of sensitive data; screenshots/clipboard.
- Network: certificate pinning expectations, http:// endpoints, allowCleartextTraffic / NSAppTransportSecurity exceptions.
- OTA updates and EAS: expo-updates signing (codeSigningCertificate), update channels, who can publish; EAS secrets usage.
- WebViews: javaScriptEnabled with untrusted origins, onMessage handlers, allowUniversalAccessFromFileURLs.
- Third-party SDK configuration (analytics, push, auth) with overly broad permissions.
- Dependency exposure actually bundled at runtime vs Metro/Jest dev chain (say which).
