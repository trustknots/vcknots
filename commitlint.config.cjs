module.exports = {
  extends: ['@commitlint/config-conventional'],
  parserPreset: {
    parserOpts: {
      headerPattern: /^(\w*)(?:\(([\w$.\-* ]*)\))?!?: (.+)$/,
      breakingHeaderPattern: /^(\w*)(?:\(([\w$.\-* ]*)\))?!: (.+)$/,
      headerCorrespondence: ['type', 'scope', 'subject'],
    },
  },
}
