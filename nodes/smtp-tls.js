var fs = require('fs');
module.exports = function(RED) {
    "use strict";

    function TLSConfig(n) {
        RED.nodes.createNode(this, config)

        // config
        const node = this
        node.valid = true;
        const certPath = config.cert.trim();
        const keyPath = config.key.trim();
        const caPath = config.ca.trim();

        if ((certPath.length > 0) || (keyPath.length > 0) || (caPath.length > 0)) {
            if ( (certPath.length > 0) !== (keyPath.length > 0)) {
                node.valid = false;
                node.error(RED._("smtp-tls.error.missing-file"));
                return;
            }
            try {
                if (certPath) {
                    node.cert = fs.readFileSync(certPath);
                }
                if (keyPath) {
                    node.key = fs.readFileSync(keyPath);
                }
                if (caPath) {
                    node.ca = fs.readFileSync(caPath);
                }
            } catch(err) {
                node.valid = false;
                node.error(err.toString());
                return;
            }
        } else {
            if (node.credentials) {
                var certData = node.credentials.certdata || "";
                var keyData = node.credentials.keydata || "";
                var caData = node.credentials.cadata || "";
                if ((certData.length > 0) !== (keyData.length > 0)) {
                    node.valid = false;
                    node.error(RED._("smtp-tls.error.missing-file"));
                    return;
                }
                if (certData) {
                    node.cert = certData;
                }
                if (keyData) {
                    node.key = keyData;
                }
                if (caData) {
                    node.ca = caData;
                }
            }
        }
    }
    RED.nodes.registerType("smtp-tls", TLSConfig, {
        credentials: {
            certdata: {type:"text"},
            keydata: {type:"text"},
            cadata: {type:"text"},
            passphrase: {type:"password"}
        },
        settings: {
            smtpTlsConfigDisableLocalFiles: {
                value: false,
                exportable: true
            }
        }
    });

    TLSConfig.prototype.addTLSOptions = function(opts) {
        if (node.valid) {
            if (node.key) {
                opts.key = node.key;
            }
            if (node.cert) {
                opts.cert = node.cert;
            }
            if (node.ca) {
                opts.ca = node.ca;
            }
            if (node.credentials && node.credentials.passphrase) {
                opts.passphrase = node.credentials.passphrase;
            }
        }
        return opts;
    }

}
