const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const session = require('express-session');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
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

app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/node_modules', express.static(path.join(__dirname, 'node_modules')));

app.use(session({
    secret: 'secreto',
    resave: false,
    saveUninitialized: true,
}));
 

app.get('/', (req, res) => {
   res.sendFile(path.join(__dirname, 'pages/cadastro/cadastro.html'));
});

app.get('/login', (req, res) => {
   res.sendFile(path.join(__dirname, 'pages/login/login.html'));
});

app.get('/usuario', (req, res) => {
   res.sendFile(path.join(__dirname, 'pages/Usuario/Usuario.html'));
});

app.get('/perfil', (req, res) => {
    res.sendFile(path.join(__dirname, 'pages/perfil/perfil.html'));
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

// Configuração do Multer
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
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

app.post('/excluir-conta', (req, res) => {
    const id_usuario = req.session.usuario_id;

    if (!id_usuario) {
        res.status(401).send('Usuário não autenticado');
        return;
    }

    const query = 'DELETE FROM usuário WHERE ID_Usuário = ?';
    conexao.query(query, [id_usuario], (erro, resultados) => {
        if (erro) {
            console.error('Erro ao excluir conta: ', erro);
            res.status(500).send('Erro ao excluir conta');
        } else {
            // Limpa a sessão após excluir a conta
            req.session.destroy((err) => {
                if (err) {
                    console.error('Erro ao destruir sessão após excluir conta:', err);
                    res.status(500).send('Erro ao excluir conta');
                } else {
                    res.status(200).send('Conta excluída com sucesso!');
                }
            });
        }
    });
});

app.post('/login-conta', async function(req, res) {
    const { email, password } = req.body;

    console.log('Corpo da requisição:', req.body); // Adiciona log para depuração
    console.log('Email recebido:', email); // Verifica o email recebido
    console.log('Password recebido:', password); // Verifica a senha recebida

    try {
        if (!email || !password) {
            console.log('Email ou senha não fornecidos'); // Adiciona log para email ou senha ausentes
            return res.status(400).send('Email ou senha não fornecidos');
        }

        // Consulta para buscar o usuário pelo email
        const [results] = await conexao.promise().query('SELECT * FROM usuário WHERE Email = ?', [email.trim()]);
        console.log('Resultados da consulta:', results); // Verifica os resultados da consulta

        if (results.length > 0) {
            const usuario = results[0];
            console.log('Usuário encontrado:', usuario); // Verifica o usuário encontrado

            // Comparar a senha usando bcrypt
            const senhaValida = await bcrypt.compare(password, usuario.Senha);
            console.log('Senha válida:', senhaValida); // Verifica a comparação de senha

            if (senhaValida) {
                req.session.usuario_id = usuario['ID_Usuário'];
                console.log('ID do usuário na sessão:', req.session.usuario_id); // Verifica se o ID do usuário está sendo armazenado corretamente
                res.redirect('/main');
            } else {
                console.log('Senha incorreta'); // Adiciona log para senha incorreta
                res.status(401).send('Credenciais inválidas: Senha incorreta.');
            }
        } else {
            console.log('Email não encontrado'); // Adiciona log para email não encontrado
            res.status(401).send('Credenciais inválidas: Email não encontrado.');
        }
    } catch (error) {
        console.error('Erro ao verificar credenciais:', error);
        res.status(500).send('Erro ao processar o login.');
    }
});






// Publicar conteúdo
app.post('/publicar', upload.single('imagem'), (req, res) => {
    try {
        const { titulo } = req.body;
        const imagem = req.file ? req.file.filename : null;
        const id_usuario = req.session.usuario_id;

        console.log('ID do usuário na sessão:', id_usuario);
        console.log('Título da publicação:', titulo);


        if (!id_usuario || !titulo) {
            return res.status(400).send('Parâmetros inválidos');
        }

        const inserePublicacaoQuery = 'INSERT INTO publicação (ID_Usuário, Título, Imagem, Data_Publicação, Status) VALUES (?, ?, ?, NOW(), "Ativa")';
        const values = [id_usuario, titulo, imagem];

        conexao.query(inserePublicacaoQuery, values, (erro, resultados) => {
            if (erro) {
                console.error('Erro ao publicar conteúdo: ', erro);
                return res.status(500).send('Erro ao publicar conteúdo');
            }

            console.log('Publicação criada com sucesso!');
            res.status(200).send('Publicação criada com sucesso!');
        });
    } catch (erro) {
        console.error('Erro ao processar requisição:', erro);
        res.status(500).send('Erro ao processar requisição');
    }
});

// Rota para visualizar publicações
app.get('/publicacoes', async (req, res) => {
    try {
        const query = `
            SELECT p.ID_Publicação, p.Título, p.Imagem, p.Data_Publicação, u.Nome AS Autor
            FROM publicação p
            JOIN usuário u ON p.ID_Usuário = u.ID_Usuário
            WHERE p.Status = 'Ativa'
            ORDER BY p.Data_Publicação DESC
        `;

        const [resultados] = await conexao.promise().query(query);

        if (resultados.length > 0) {
            res.status(200).json(resultados);
        } else {
            res.status(404).send('Nenhuma publicação encontrada.');
        }
    } catch (erro) {
        console.error('Erro ao buscar publicações: ', erro);
        res.status(500).send('Erro ao buscar publicações');
    }
});

app.post('/editar-perfil', async (req, res) => {
    const { nome, email, senhaAtual, novaSenha } = req.body;
    const id_usuario = req.session.usuario_id;

    try {
        if (!id_usuario) {
            throw new Error('Usuário não autenticado');
        }
        const [usuario] = await conexao.execute('SELECT * FROM usuário WHERE ID_Usuário = ?', [id_usuario]);
        if (!usuario) {
            throw new Error('Usuário não encontrado');
        }

        const senhaValida = await bcrypt.compare(senhaAtual, usuario.Senha);
        if (!senhaValida) {
            throw new Error('Senha atual incorreta');
        }

        let hashedPassword = null;
        if (novaSenha) {
            hashedPassword = await bcrypt.hash(novaSenha, 10);
        }

        const updateQuery = 'UPDATE usuário SET Nome = ?, Email = ?, Senha = ? WHERE ID_Usuário = ?';
        const [resultados] = await conexao.execute(updateQuery, [nome, email, hashedPassword || usuario.Senha, id_usuario]);

        if (resultados.affectedRows === 1) {
            res.status(200).send('Perfil atualizado com sucesso!');
        } else {
            res.status(500).send('Erro ao atualizar perfil');
        }
    } catch (erro) {
        console.error('Erro ao editar perfil: ', erro);
        res.status(500).send('Erro ao editar perfil');
    }
});


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