const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const session = require('express-session');

const app = express();

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

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'testeweb42@gmail.com',
        pass: 'ucwz ybdh xtws fqoh'
    }
});

app.use(session({
    secret: 'secreto',
    resave: false,
    saveUninitialized: true,
}));

app.use(express.static(path.join(__dirname, 'public')));

app.use('/node_modules', express.static(path.join(__dirname, 'node_modules')));
 

app.get('/', (req, res) => {
   res.sendFile(path.join(__dirname, 'pages/cadastro/cadastro.html'));
});

app.get('/login', (req, res) => {
   res.sendFile(path.join(__dirname, 'pages/login/login.html'));
});

app.get('/usuario', (req, res) => {
   res.sendFile(path.join(__dirname, 'pages/Usuario/Usuario.html'));
});

app.get('/administrador', (req, res) => {
    res.sendFile(path.join(__dirname, 'pages/Admin/administrador.html'));
});

app.get('/gerencia', (req, res) => {
    res.sendFile(path.join(__dirname, 'pages/Admin/gerencia.html'));
});

app.get('/denuncias', (req, res) => {
    res.sendFile(path.join(__dirname, 'pages/Admin/administrador.html'));
});

app.get('/main', (req, res) => {
    res.sendFile(path.join(__dirname, 'pages/main/main.html'));
});

app.get('/cadastro', (req, res) => {
    res.sendFile(path.join(__dirname, 'pages/cadastro2/cadastro2.html'));
});

app.get('/confirm', (req, res) => {
    const { token } = req.query;
    console.log('Token recebido na URL:', token); // Adicionar log para depuração

    const query = 'SELECT * FROM usuário WHERE confirmation_token = ?';
    conexao.query(query, [token], (erro, resultados) => {
        if (erro) {
            console.error('Erro ao confirmar usuário:', erro);
            res.status(500).send('Erro ao confirmar usuário');
        } else if (resultados.length === 0) {
            console.error('Token não encontrado ou inválido:', token);
            res.status(400).send('Token inválido ou expirado');
        } else {
            // Redireciona para a página onde o cadastro será completado
            res.redirect(`/cadastro?token=${token}`);
        }
    });
});




// funcionalidades: 

// Cadastro
app.post('/autentication_email', (req, res) => {
    const { email } = req.body;
    const confirmationToken = crypto.randomBytes(20).toString('hex');

    const query = 'INSERT INTO usuário (Email, confirmation_token) VALUES (?, ?)';
    conexao.query(query, [email, confirmationToken], (erro, resultados) => {
        if (erro) {
            console.error('Erro ao inserir token de confirmação no banco de dados: ', erro);
            res.status(500).send('Erro ao enviar email de confirmação');
        } else {
            const confirmationUrl = `http://localhost:8081/confirm?token=${confirmationToken}`;

            const mailOptions = {
                from: 'seu-email@gmail.com',
                to: email,
                subject: 'Confirme seu cadastro',
                html: `<p>Por favor, clique no link abaixo para confirmar seu cadastro:</p><p><a href="${confirmationUrl}">${confirmationUrl}</a></p>`
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error('Erro ao enviar email: ', error);
                    res.status(500).send('Erro ao enviar email de confirmação');
                } else {
                    res.status(200).send('Email de confirmação enviado! Por favor, verifique seu email.');
                }
            });
        }
    });
});



app.post('/criar-conta', async (req, res) => {
    const { token, nome, senha } = req.body;

    console.log('Token recebido na rota /criar-conta:', token); // Verifica o token recebido

    try {
        // Hash da senha usando bcrypt
        const hashedPassword = await bcrypt.hash(senha, 10);

        // Verifica se o token é válido e seleciona os dados do usuário
        const selectQuery = 'SELECT * FROM usuário WHERE confirmation_token = ?';
        const [resultados] = await conexao.promise().query(selectQuery, [token]);

        // Verifica se encontrou o usuário com o token
        if (resultados.length === 0) {
            console.error(`Token não encontrado ou inválido: ${token}`);
            return res.status(400).send('Token inválido ou expirado');
        }

        // Atualiza o registro do usuário
        const updateQuery = 'UPDATE usuário SET Nome = ?, Senha = ?, confirmed = true, confirmation_token = NULL WHERE confirmation_token = ?';
        const [updateResultados] = await conexao.promise().query(updateQuery, [nome, hashedPassword, token]);

        if (updateResultados.affectedRows === 0) {
            console.error(`Nenhum registro atualizado para o token: ${token}`);
            return res.status(400).send(`Nenhum registro atualizado para o token: ${token}`);
        }

    } catch (erro) {
        console.error('Erro ao completar cadastro: ', erro);
        res.status(500).send('Erro ao completar cadastro');
    }
});


// Login do usuário
// app.post('/login', (req, res) => {
//     const { nome, senha } = req.body;
    
//     const query = 'SELECT * FROM usuário WHERE Nome = ?';
//     conexao.query(query, [nome], async (erro, resultados) => {
//         if (erro) {
//             console.error('Erro ao verificar nome: ', erro);
//             res.status(500).send('Erro ao fazer login');
//             return;
//         }

//         if (resultados.length === 0) {
//             res.status(400).send('Nome ou senha inválidos');
//             return;
//         }

//         const usuario = resultados[0];

//         const senhaValida = await bcrypt.compare(senha, usuario.Senha);
//         if (!senhaValida) {
//             res.status(400).send('Nome ou senha inválidos');
//         } else {
//             res.status(200).send('Login bem-sucedido');
//         }
//     });
// });

app.post('/login', function(req, res) {
    const { email, password } = req.body;
  
    conexao.query('SELECT * FROM usuário WHERE Email = ?', [email], async function(error, results) {
        if (error) {
            console.error('Erro ao verificar credenciais:', error);
            res.status(500).send('Erro ao processar o login.');
            return;
        }
        
        if (results.length > 0) {
            const usuario = results[0];
            const senhaValida = await bcrypt.compare(password, usuario.Senha);
            
            if (senhaValida) {
                // Armazenar o ID do usuário na sessão
                req.session.usuario_id = usuario.ID;
                res.redirect('/main');
            } else {
                res.status(401).send('Credenciais inválidas.');
            }
        } else {
            res.status(401).send('Credenciais inválidas.');
        }
    });
});


// Publicar conteúdo
// app.post('/publicar', upload.single('imagem'), (req, res) => {
//     const { id_usuario, titulo, conteudo } = req.body;
//     const imagem = req.file ? req.file.filename : null;

//     const query = 'INSERT INTO Publicação (ID_Usuário, Título, Conteúdo, Data_Publicação, Status, Imagem) VALUES (?, ?, ?, NOW(), "Ativa", ?)';
//     conexao.query(query, [id_usuario, titulo, conteudo, imagem], (erro, resultados) => {
//         if (erro) {
//             console.error('Erro ao publicar conteúdo: ', erro);
//             res.status(500).send('Erro ao publicar conteúdo');
//         } else {
//             res.status(200).send('Publicação criada com sucesso!');
//         }
//     });
// });

// Adicionar comentário
app.post('/comentar', (req, res) => {
    const { id_publicacao, id_usuario, conteudo } = req.body;

    const query = 'INSERT INTO Comentário (ID_Publicação, ID_Usuário, Conteúdo, Data_Comentário) VALUES (?, ?, ?, NOW())';
    conexao.query(query, [id_publicacao, id_usuario, conteudo], (erro, resultados) => {
        if (erro) {
            console.error('Erro ao adicionar comentário: ', erro);
            res.status(500).send('Erro ao adicionar comentário');
        } else {
            res.status(200).send('Comentário adicionado com sucesso!');
        }
    });
});

// Denunciar publicação
app.post('/denunciar', (req, res) => {
    const { id_publicacao, id_usuario, motivo } = req.body;

    const query = 'INSERT INTO Denúncia (ID_Publicação, ID_Usuário, Motivo, Data_Denúncia, Status) VALUES (?, ?, ?, NOW(), "Pendente")';
    conexao.query(query, [id_publicacao, id_usuario, motivo], (erro, resultados) => {
        if (erro) {
            console.error('Erro ao denunciar publicação: ', erro);
            res.status(500).send('Erro ao denunciar publicação');
        } else {
            res.status(200).send('Denúncia registrada com sucesso!');
        }
    });
});



app.listen(8081, function() {
    console.log("Servidor Rodando na url http://localhost:8081");
});   