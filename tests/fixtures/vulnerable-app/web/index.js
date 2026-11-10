// Test fixture: intentionally unsafe code for exercising the SAST scanners.
const { exec } = require("child_process");
const http = require("http");
const url = require("url");

http
  .createServer((req, res) => {
    const query = url.parse(req.url, true).query;
    exec("ls " + query.dir, (error, stdout) => {
      res.end(stdout);
    });
    if (query.expr) {
      res.end(String(eval(query.expr)));
    }
  })
  .listen(8080);
