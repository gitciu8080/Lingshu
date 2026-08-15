//
// aspxraw::asmx 编码模块
//
// :asmx类型WebShell
//

'use strict';

module.exports = (pwd, data, ext = null) => {
  ext.opts['httpConf']['headers']['content-type'] = 'text/xml; charset=utf-8'
  data[pwd] = `<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Invoke xmlns="http://tempuri.org/"><${pwd}>${data['_']}</${pwd}></Invoke></soap:Body></soap:Envelope>`;

  delete data['_'];
  return data;
}