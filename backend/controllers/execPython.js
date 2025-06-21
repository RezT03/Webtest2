const { spawn } = require('child_process');
const path = require('path');

exports.execPython = (scriptName, args = []) => {
  return new Promise((resolve, reject) => {
    const scriptPath = path.join(__dirname, scriptName);
    const process = spawn('python3', [scriptPath, ...args]);

    let output = '';
    let error = '';

    process.stdout.on('data', (data) => {
      output += data.toString();
    });

    process.stderr.on('data', (data) => {
      error += data.toString();
    });

    process.on('close', (code) => {
      if (code === 0) {
        resolve(output.trim());
      } else {
        reject(`Python exited with code ${code}:\n${error}`);
      }
    });
  });
};
