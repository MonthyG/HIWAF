OWASP CRS rule-exclusion plugins, vendored unchanged from these releases:

| Directory  | Source                                              | Release |
|------------|-----------------------------------------------------|---------|
| wordpress  | github.com/coreruleset/wordpress-rule-exclusions-plugin  | v1.2.0 |
| drupal     | github.com/coreruleset/drupal-rule-exclusions-plugin     | v1.0.0 |
| nextcloud  | github.com/coreruleset/nextcloud-rule-exclusions-plugin  | v1.7.1 |
| phpmyadmin | github.com/coreruleset/phpmyadmin-rule-exclusions-plugin | v1.1.0 |
| dokuwiki   | github.com/coreruleset/dokuwiki-rule-exclusions-plugin   | v1.0.0 |
| phpbb      | github.com/coreruleset/phpbb-rule-exclusions-plugin      | v1.0.0 |
| xenforo    | github.com/coreruleset/xenforo-rule-exclusions-plugin    | v1.0.0 |

Each directory holds the release's `plugins/*.conf` and its Apache-2.0 `LICENSE`.

`graphql` is HI WAF's own profile, not a CRS release: it lets the rules that
misread GraphQL syntax skip the `query` field on `/graphql` (see the file's comments).
To update one, replace its files with a newer release's and change the version in
`../crsplugins.go`.
