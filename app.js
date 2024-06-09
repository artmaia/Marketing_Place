const express = require('express');
// const session = require('express-session');
const path = require('path');
const app = express();

const mysql = require('mysql2');

app.use(express.json());
app.use(express.urlencoded({extended:false}));

const conexao = mysql.createConnection({
    host:'localhost',
    user:'root', 
    password:'1234',
    database:'marketingplace'
});

conexao.connect(function(erro){
    if(erro) throw erro;
    console.log('Conexao bem sucedida');
})

app.use(express.static(path.join(__dirname, 'public')));  

app.listen(8081, function() {
    console.log("Servidor Rodando na url http://localhost:8081");
});   