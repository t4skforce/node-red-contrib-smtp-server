
module.exports = function (RED) {
  'use strict'
  const SMTPServer = require('smtp-server').SMTPServer
  const SimpleParser = require('mailparser').simpleParser;
  const os = require('os')

  function SmtpServerNode (config) {
    RED.nodes.createNode(this, config)

    // config
    const node = this
    const listen = config.listen || '127.0.0.1'
    const port = config.port || 8025
    const usetls = config.usetls === true
    const tls = config.tls || undefined
    const hostname = config.hostname || os.hostname()
    const banner = config.banner || ''
    const size = config.size || undefined
    const hideSize = config.hideSize || false
    const users = config.users || []
    const authMethods = (config.authMethods || 'PLAIN, LOGIN').split(',').map(v => v.toUpperCase().trim())
    const authOptional = config.authOptional === true || users.length === 0 || authMethods.length === 0
    const hideSTARTTLS = config.hideSTARTTLS === true
    const hidePIPELINING = config.hidePIPELINING === true
    const hide8BITMIME = config.hide8BITMIME === true
    const hideSMTPUTF8 = config.hideSMTPUTF8 === true
    const allowInsecureAuth = config.allowInsecureAuth === true
    const disableReverseLookup = config.disableReverseLookup === true
    const maxClients = config.maxClients || -1
    const useProxy = config.useProxy === true
    const useXClient = config.useXClient === true
    const useXForward = config.useXForward === true
    const lmtp = config.lmtp === true
    const socketTimeout = (config.socketTimeout || 60) * 1000
    const closeTimeout = (config.closeTimeout || 30) * 1000


    if(authOptional === true) {
        node.warn('Authentification is optional as per configuration');
    }

    // parser
    const maxHtmlLengthToParse = config.maxHtmlLengthToParse || undefined
    const skipHtmlToText = config.skipHtmlToText === true
    const skipTextToHtml = config.skipTextToHtml === true
    const skipImageLinks = config.skipImageLinks === true
    const skipTextLinks = config.skipTextLinks === true

    // tls
    const key = config.key || null
    const passphrase = config.passphrase || null // for key file
    const cert = config.cert || null

    var options = {
      name:hostname,
      banner:banner,
      size:size,
      authOptional:authOptional,
      secure: usetls,
      onConnect (session, callback) {
        // check allowed IP's
        node.status({ fill: 'green', shape: 'dot', text: `${session.remoteAddress} - connected` })
        return callback() // pass through
      },
      onAuth (auth, session, callback) {
        if(auth.username === username) {
            if ((auth.method === 'PLAIN' || auth.method === 'LOGIN') && (auth.password === password || password === undefined)) {
              return callback(null,{ user:auth.username }) // pass through
            } else if(auth.method === "XOAUTH2" && auth.accessToken === password) {
              return callback(null,{ user:auth.username }) // pass through
            } else if(auth.method === "CRAM-MD5" && auth.validatePassword(password)) {
              return callback(null,{ user:auth.username }) // pass through
            }
        } else if(authOptional) {
          return callback(null,{user:session.remoteAddress}) // pass through
        }

        node.status({ fill: 'red', shape: 'dot', text: `error auth (${session.remoteAddress})` })
        if (auth.method === 'XOAUTH2') {return callback(null,{data:{status:'401',schemes:'bearer mac',scope:'https://mail.google.com/'}});}
        return callback(new Error("Invalid authentification"))
      },
      onMailFrom (address, session, callback) {
        // check allowed from mail
        return callback() // pass through
      },
      onRcptTo (address, session, callback) {
        // check allowed to main
        return callback() // pass through
      },
      onData (stream, session, callback) {
        SimpleParser(stream, {
          maxHtmlLengthToParse:maxHtmlLengthToParse,
          skipHtmlToText:skipHtmlToText,
          skipTextToHtml:skipTextToHtml,
          skipImageLinks:skipImageLinks,
          skipTextLinks:skipTextLinks
        })
        .then(mailMessage => {
          var msg = {
            topic: mailMessage.subject,
            date: mailMessage.date,
            payload: mailMessage.text
          };
          msg.header = {};
          mailMessage.headers.forEach((v, k) => {msg.header[k] = v;});
          if (mailMessage.html) { msg.html = mailMessage.html; }
          if (mailMessage.to && mailMessage.to.length > 0) { msg.to = mailMessage.to; }
          if (mailMessage.cc && mailMessage.cc.length > 0) { msg.cc = mailMessage.cc; }
          if (mailMessage.bcc && mailMessage.bcc.length > 0) { msg.bcc = mailMessage.bcc; }
          if (mailMessage.from && mailMessage.from.value && mailMessage.from.value.length > 0) { msg.from = mailMessage.from.value[0].address; }
          if (mailMessage.attachments) { msg.attachments = mailMessage.attachments; }
          else { msg.attachments = []; }
          node.send(msg);
        })
        .catch(err => {
          node.status({ fill: 'red', shape: 'dot', text: 'parser error' })
          node.error(`Error ${err.message}`)
        });
        stream.on("end", callback);
      },
      onClose (session) {
        //node.status({ fill: 'green', shape: 'dot', text: `${listen}:${port} - ready` })
      }
    }

    const server = new SMTPServer(options)
    node.log(`Binding smtp-server on ${listen}:${port}`)
    server.listen(port, listen, function () {
      node.log(`smtp-server running on ${listen}:${port}`)
      node.status({ fill: 'green', shape: 'dot', text: `${listen}:${port} - ready` })
    })

    server.on('error', err => {
      node.status({ fill: 'red', shape: 'dot', text: 'server error' })
      node.error(`Error ${err.message}`)
    })

    node.on('close', function (done) {
      node.log(`Unbinding smtp-server on ${listen}:${port}`)
      server.close(done || function () {})
    })

    node.status({ fill: 'blue', shape: 'ring', text: `${listen}:${port} - idle` })
  }

  RED.nodes.registerType('smtp-server', SmtpServerNode, {
    credentials: {
        username: {type: 'text'},
        password: {type: 'password'}
    }
  })
}
