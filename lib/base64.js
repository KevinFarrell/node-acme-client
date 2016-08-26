
function toBase64(input, encoding='utf8') {
  return new Buffer(input, encoding).toString('base64');
}

function toBase64Url(input, encoding='utf8') {
  return toBase64(input, encoding).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

module.exports = {toBase64, toBase64Url};
