# pe-parser [![build](https://github.com/jirsh/pe-parser/actions/workflows/npm-publish.yml/badge.svg)](https://github.com/jirsh/pe-parser/actions/workflows/npm-publish.yml)

PE Parser for Node.JS applications

### Validation example

```js
// The Validate promise throws if the PE file is invalid
try {
  const { architecture } = await Validate(file); // returns either 'x64' or 'x86'

  console.log(architecture);
} catch (e) {
  console.error(e);
}
```
