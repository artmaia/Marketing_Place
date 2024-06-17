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

app.use('/node_modules', express.static(path.join(__dirname, 'node_modules')));
 

app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
   res.sendFile(path.join(__dirname, 'pages/cadastro/cadastro.html'));
});

// app.get('/login', (req, res) => {
//    res.sendFile(path.join(__dirname, 'pages/Login/login.html'));
// });

// app.get('/usuario', (req, res) => {
//    res.sendFile(path.join(__dirname, 'pages/Usuario/Usuario.html'));
// });

// app.get('/administrador', (req, res) => {
//     res.sendFile(path.join(__dirname, 'pages/Admin/administrador.html'));
// });

app.listen(8081, function() {
    console.log("Servidor Rodando na url http://localhost:8081");
});   