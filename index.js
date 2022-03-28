const request = require('request');
const fs = require('fs');
require('dotenv').config()

const analyzeFile = async (path) =>{
    return new Promise((resolve, reject) => {
      request({
        url: 'https://www.virustotal.com/api/v3/files',
        method: 'POST',
        headers: {'x-apikey': process.env.APIKEY, "Content-Type": "multipart/form-data"},
        formData: {file: fs.createReadStream(path)}
      }, async (err, res) => {
        !err ? resolve(res) : reject(err);
      });

    });
  }
const reporteFile = async (id) => {
    return new Promise((resolve, reject) => {
        request({
            url: 'https://www.virustotal.com/api/v3/analyses/' + id,
            method: 'GET',
            headers: {'x-apikey': process.env.APIKEY},
        }, async (err, res) => {
            !err ? resolve(res) : reject(err);
        });
    });
}

const checkFile = async (file) => {
    const datos = await analyzeFile( file )
    const id = JSON.parse(datos.body).data.id;
    const report = await reporteFile(id)
    const informe = JSON.parse(report.body)
    const results = informe.data.attributes.results
    var hasVirus = false
    for(let result in results){
        var itemActual = results[result]
        if (itemActual.result != null) {
            hasVirus = true
            console.log(result + " => " +itemActual.result)
        }
    }
    if (!hasVirus) {
        console.log("No virus found")
    }
}

const main = async () => {
    var files = fs.readdirSync("../pids/" ) 
    for(var i=0; i < files.length; i++){
        const file = files[i]
        console.log(file)
       await checkFile("../pids/" + file);
    };
}


main()
