let helper = require("node-red-node-test-helper");
let smtpServer = require("../nodes/smtp-server.js");
let nodemailer = require('nodemailer');

describe('smtp-server Node', function () {

  afterEach(function () {
    helper.unload();
  });

  it('should be loaded', function (done) {
    var flow = [{ id: "n1", type: "smtp-server", name: "test server" }];
    helper.load(smtpServer, flow, function () {
      var n1 = helper.getNode("n1");
      n1.should.have.property('name', 'test server');
      done();
    });
  });

  it('should receive text mail', function (done) {
    var flow = [{
      id: "n1",
      type: "smtp-server",
      name: "test server",
      listen: '127.0.0.1',
      port: 9999,
      usetls:false,
      authOptional:true,
      wires:[["n2"]]
    },{
      id: "n2",
      type: "helper"
    }];
    helper.load(smtpServer, flow, function () {
      var n2 = helper.getNode("n2");
      var n1 = helper.getNode("n1");

      n2.on('input', function (msg) {
        try {
          msg.should.have.property('topic', 'Hello ✔');
          msg.should.have.property('payload', 'Hello world?\n');
          msg.should.have.property('from', '"Fred Foo 🌎" <foo@example.com>');
          msg.should.have.property('to', '"Sam Bar 🌢" <to@email.com>');
          done();
        } catch(e) {
          console.log(msg);
          done(e);
        }
      });

      nodemailer.createTransport({
          host: '127.0.0.1',
          port: 9999,
          secure: false,
          tls: {
            rejectUnauthorized: false
          }
      }).sendMail({
        from: '"Fred Foo 🌎" <foo@example.com>',
        to: '"Sam Bar 🌢" <to@email.com>',
        subject: 'Hello ✔',
        text: 'Hello world?\n'
      }, function(err, info) {
        if (err) {
          done(err);
        }
      });
    });
  });


});
