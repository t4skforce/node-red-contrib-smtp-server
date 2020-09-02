
module.exports = function (RED) {
  'use strict'
  const SMTPServer = require('smtp-server').SMTPServer
  const SimpleParser = require('mailparser').simpleParser
  const os = require('os')
  const ip6addr = require('ip6addr')

  function SmtpServerNode (config) {
    RED.nodes.createNode(this, config)

    // config
    const node = this
    const context = node.context()

    const listen = config.listen || '127.0.0.1'
    const port = config.port || 8025
    const usetls = config.usetls === true
    const tls = config.tls || undefined
    const hostname = config.hostname || os.hostname()
    const banner = config.banner || ''
    const size = config.size || undefined
    const hideSize = config.hideSize || false
    const users = config.users || []
    const authMethods = config.authMethods || ['PLAIN, LOGIN','CRAM-MD5']
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
    const ipFilter = config.ipFilter === true
    const ip = config.ip || []
    const fromFilter = config.fromFilter === true
    const from = config.from || []
    const toFilter = config.toFilter === true
    const to = config.to || []
    const disabledCommands = config.disabledCommands || []


    if(authOptional === true) {
        if(config.authOptional === true) {
          node.warn('Authentification disabled: Security -> Optional Authentication');
        } else if(users.length === 0) {
          node.warn('Authentification disabled: Authentification -> Users is empty');
        } else if(authMethods.length === 0) {
          node.warn('Authentification disabled: Authentification -> Methods is empty');
        } else {
          node.warn('Authentification disabled');
        }
    }

    // parser
    const maxHtmlLengthToParse = config.maxHtmlLengthToParse || undefined
    const skipHtmlToText = config.skipHtmlToText === true
    const skipTextToHtml = config.skipTextToHtml === true
    const skipImageLinks = config.skipImageLinks === true
    const skipTextLinks = config.skipTextLinks === true

    // TODO: tls
    const key = config.key || null
    const passphrase = config.passphrase || null // for key file
    const cert = config.cert || null

    var options = {
      name:hostname,
      banner:banner,
      size:size,
      authOptional:authOptional,
      secure: usetls,
      logger: false,
      maxAllowedUnauthenticatedCommands: Number.MAX_SAFE_INTEGER,
      onConnect (session, callback) {
        if(ipFilter === true) {
          const found = ip.find(obj => ip6addr.createCIDR(obj.ip).contains(session.remoteAddress));
          if(found !== undefined) {
            node.status({ fill: 'green', shape: 'dot', text: `${session.remoteAddress} - connected` })
            return callback()
          } else {
            node.status({ fill: 'red', shape: 'dot', text: `IP blocked - ${session.remoteAddress}` })
            node.warn(`IP blocked: ${session.remoteAddress}`)
            return callback(new Error("Try again later"))
          }
        } else {
          node.status({ fill: 'green', shape: 'dot', text: `${session.remoteAddress} - connected` })
          return callback()
        }
      },
      onAuth (auth, session, callback) {
        if(users.length > 0) {
          var user = undefined;
          if (auth.method === 'PLAIN' || auth.method === 'LOGIN' || auth.method === "XOAUTH2") {
            user = users.find(u => u.u === auth.username && u.p === auth.password)
          } else if(auth.method === "CRAM-MD5") {
            user = users.find(u => u.u === auth.username && auth.validatePassword(u.p))
          }
          if(user) {
            return callback(null,{ user:user.username })
          }
        } else if(authOptional) {
          return callback(null,{ user:session.remoteAddress }) // pass through
        }
        node.status({ fill: 'red', shape: 'dot', text: `error auth (${session.remoteAddress})` })
        node.warn(`Error Authenticating (ip:${session.remoteAddress}, user:${auth.username}, pass:${auth.password})`)
        if (auth.method === 'XOAUTH2') {
          return callback(null,{data:{status:'401',schemes:'bearer mac',scope:'https://mail.google.com/'}})
        }
        return callback(new Error("Authentication failed"))
      },
      onMailFrom (address, session, callback) {
        if(fromFilter === true) {
          const match = from.find(function(obj) {
            if(obj.t === 're') {
              return (new RegExp(obj.v,'i')).test(address.address);
            } else if(obj.t === 'str') {
              return obj.v.toString().toLowerCase().trim() === address.address.toLowerCase().trim();
            } else if(obj.t === 'flow') {
              return context.flow.get(obj.v).toString().toLowerCase().trim() === address.address.toLowerCase().trim();
            } else if(obj.t === 'global') {
              return context.global.get(obj.v).toString().toLowerCase().trim() === address.address.toLowerCase().trim();
            } else if(obj.t === 'env') {
              return node._flow.getSetting(obj.v).toString().toLowerCase().trim() === address.address.toLowerCase().trim();
            }
            return false;
          });
          if(match !== undefined) {
            node.status({ fill: 'green', shape: 'dot', text: `${session.remoteAddress} - from` })
            return callback()
          }
          node.status({ fill: 'red', shape: 'dot', text: `Invalid From - ${address}` })
          node.warn(`Invalid from address: ${address}`)
          return callback(new Error("Not accepted"))
        } else {
          return callback() // pass through
        }
      },
      onRcptTo (address, session, callback) {
        if(toFilter === true) {
          const match = to.find(function(obj) {
            if(obj.t === 're') {
              return (new RegExp(obj.v,'i')).test(address.address);
            } else if(obj.t === 'str') {
              return obj.v.toString().toLowerCase().trim() === address.address.toLowerCase().trim();
            } else if(obj.t === 'flow') {
              return context.flow.get(obj.v).toString().toLowerCase().trim() === address.address.toLowerCase().trim();
            } else if(obj.t === 'global') {
              return context.global.get(obj.v).toString().toLowerCase().trim() === address.address.toLowerCase().trim();
            } else if(obj.t === 'env') {
              return node._flow.getSetting(obj.v).toString().toLowerCase().trim() === address.address.toLowerCase().trim();
            }
            return false;
          });
          if(match !== undefined) {
            node.status({ fill: 'green', shape: 'dot', text: `${session.remoteAddress} - to` })
            return callback()
          }
          node.status({ fill: 'red', shape: 'dot', text: `Invalid To - ${address}` })
          node.warn(`Invalid To address: ${address}`)
          return callback(new Error("Not accepted"))
        } else {
          return callback() // pass through
        }
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
            payload: mailMessage.text,
            header: {},
            session: {
              id: session.id,
              remoteAddress: session.remoteAddress,
              clientHostname: session.clientHostname,
              user: session.user,
              transmissionType: session.transmissionType
            },
            messageId: mailMessage.messageId
          };

          var addrToString = function(addrs) {
            var retVal = [];
            addrs.forEach((addr) => {
              if(addr.name && addr.name.trim() !== "") {
                retVal.push(`${addr.name} <${addr.address}>`)
              } else {
                retVal.push(addr.address)
              }
            });
            return retVal.join(';');
          };

          mailMessage.headers.forEach((v, k) => {msg.header[k] = v;});
          if (mailMessage.html) { msg.html = mailMessage.html; }
          if (mailMessage.to && mailMessage.to.value && mailMessage.to.value.length > 0) {
            msg.to = addrToString(mailMessage.to.value);
          }
          if (mailMessage.cc && mailMessage.cc.value && mailMessage.cc.value.length > 0) {
            msg.cc = addrToString(mailMessage.cc.value);
          }
          if (mailMessage.bcc && mailMessage.bcc.value && mailMessage.bcc.value.length > 0) {
            msg.bcc = addrToString(mailMessage.bcc.value);
          }
          if (mailMessage.from && mailMessage.from.value && mailMessage.from.value.length > 0) {
            msg.from = addrToString(mailMessage.from.value);
          }
          if (mailMessage.replyTo && mailMessage.replyTo.value && mailMessage.replyTo.value.length > 0) {
            msg.replyTo = addrToString(mailMessage.replyTo.value);
          }
          if (mailMessage.inReplyTo) {
            msg.inReplyTo = mailMessage.inReplyTo;
          }
          if (mailMessage.references) {
            msg.references = mailMessage.references;
          }
          msg.attachments = (mailMessage.attachments)?mailMessage.attachments:[];
          node.send(msg);
          node.status({ fill: 'green', shape: 'dot', text: `${session.remoteAddress} - sendt` })
        })
        .catch(err => {
          node.status({ fill: 'red', shape: 'dot', text: 'parser error' })
          node.error(`Error ${err.message}`)
        });
        stream.on("end", callback);
      },
      onClose (session) {
        // node.status({ fill: 'green', shape: 'dot', text: `${listen}:${port} - ready` })
      }
    }

    node.warn({
      options:options,
      users:users,
      ip:ip,
      from:from,
      to:to,
      disabledCommands:disabledCommands,
      maxClients: config.maxClients
    });

    const server = new SMTPServer(options)
    node.log(`Binding smtp-server on ${listen}:${port}`)
    server.listen(port, listen, function () {
      node.log(`smtp-server running on ${listen}:${port}`)
      node.status({ fill: 'green', shape: 'dot', text: `${listen}:${port} - ready` })
    })

    server.on('error', err => {
      node.status({ fill: 'red', shape: 'dot', text: 'server error' })
      node.error({payload:"smtp-server Error",error:err})
    })

    node.on('close', function (done) {
      node.log(`Unbinding smtp-server on ${listen}:${port}`)
      server.close(done || function () {})
    })

    node.status({ fill: 'blue', shape: 'ring', text: `${listen}:${port} - idle` })
  }

  RED.httpAdmin.post('/smtp-server/validate/ip', RED.auth.needsPermission('smtp-server.read'), (req, res) => {
    const nodeIP = req.body.ip
    try {
      ip6addr.parse(nodeIP)
      res.json({ valid: true })
    } catch(error) {
      res.json({ valid: false, error: error.message })
    }
  })

  RED.httpAdmin.post('/smtp-server/validate/cidr', RED.auth.needsPermission('smtp-server.read'), (req, res) => {
    const nodeCIDR = req.body.cidr
    try {
      ip6addr.createCIDR(nodeCIDR)
      res.json({ valid: true })
    } catch(error) {
      res.json({ valid: false, error: error.message })
    }
  })

  RED.nodes.registerType('smtp-server', SmtpServerNode, {
    credentials: {
        username: {type: 'text'},
        password: {type: 'password'}
    }
  })

}
