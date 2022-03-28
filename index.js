const request = require('request');
const fs = require('fs');
require('dotenv').config()
const logger = require('./log.js')

const analyzeFile = (path) =>{
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
const reporteFile = (id) => {
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
const askAnalyzeFile = async (file) => {
    const datos = await analyzeFile( file )
    const id = JSON.parse(datos.body).data.id;
    return id
}

const checkFile = async (id) => {
    const report = await reporteFile(id)
    const informe = JSON.parse(report.body)
    const results = informe.data.attributes.results
    var retorn = []
    for(let result in results){
        var itemActual = results[result]
        if (itemActual.result != null) {
            retorn.push({enginy: result, result : itemActual.result })
        }
    }
    return retorn
}


const main = async () => {
    var vtFiles = []
    var files = fs.readdirSync("../pids2/" ) 
    for(var i=0; i < files.length; i++){
        const file = files[i]
        const id = await askAnalyzeFile("../pids2/" +file)
        vtFiles.push({file:file, id:id})
        logger.info("Analyzing file " + file + " : " + id)
    }
    for(var i=0; i < vtFiles.length; i++){
        logger.info("check result:" + vtFiles[i].file+" : "+vtFiles[i].id)
        const info = await checkFile(vtFiles[i].id)
        if(info.length == 0) {
            logger.info("No virus found")
        } else {
            logger.crit(JSON.stringify(info))
        }
    }
}


main()
