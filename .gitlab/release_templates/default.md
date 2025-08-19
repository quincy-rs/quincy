## Changes

{{#each changes}}
{{#unless (contains labels "dependencies")}}
- {{title}} by @{{author.username}} in {{web_url}}
{{/unless}}
{{/each}}

{{#if dependencies}}
## Dependencies

{{#each changes}}
{{#if (contains labels "dependencies")}}
- {{title}} by @{{author.username}} in {{web_url}}
{{/if}}
{{/each}}
{{/if}}

**Full Changelog**: {{compare_url}}