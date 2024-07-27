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
    cookie: { 
        secure: false,
        httpOnly: true,
        sameSite: 'Lax'
    }
}));


async function verificarAutenticacao(req, res, next) {
    const userId = req.session.usuario_id;

    if (!userId) {
        return res.status(401).json({ message: 'Usuário não autenticado' });
    }

    try {
        const [resultados] = await conexao.promise().query('SELECT Bloqueado FROM usuário WHERE ID_Usuário = ?', [userId]);

        if (resultados.length === 0) {
            return res.status(404).json({ message: 'Usuário não encontrado' });
        }

        const usuario = resultados[0];

        if (usuario.Bloqueado) {
            req.session.destroy(); // Destruir a sessão se o usuário estiver bloqueado
            return res.status(403).json({ message: 'Sua conta está bloqueada. Contate o suporte.' });
        }

        next(); // Usuário autenticado e não bloqueado
    } catch (erro) {
        console.error('Erro ao verificar status do usuário: ', erro);
        res.status(500).json({ message: 'Erro ao verificar status do usuário' });
    }
}

// function verificarUsuarioBloqueado(req, res, next) {
//     const userId = req.session.userId; // Assumindo que você armazena o ID do usuário na sessão

//     if (!userId) {
//         return next();
//     }

//     const sql = `SELECT Bloqueado FROM usuário WHERE ID_Usuário = ?`;

//     conexao.query(sql, [userId], (err, result) => {
//         if (err || result.length === 0 || result[0].Bloqueado === 1) {
//             req.session.destroy(); // Destruir a sessão se o usuário estiver bloqueado
//             return res.redirect('/login'); // Redirecionar para a página de login
//         }
//         next();
//     });
// }


app.get('/api/usuario', verificarAutenticacao, async (req, res) => {
    const userId = req.session.usuario_id;

    try {
        const [resultados] = await conexao.promise().query('SELECT * FROM usuário WHERE ID_Usuário = ?', [userId]);

        if (resultados.length === 0) {
            return res.status(404).json({ message: 'Usuário não encontrado' });
        }

        const usuario = resultados[0];
        res.json(usuario);
    } catch (erro) {
        console.error('Erro ao obter dados do usuário: ', erro);
        res.status(500).json({ message: 'Erro ao obter dados do usuário' });
    }
});
 
app.get('/', (req, res) => {
   res.sendFile(path.join(__dirname, 'pages/cadastro/cadastro.html'));
});

app.get('/login', (req, res) => {
   res.sendFile(path.join(__dirname, 'pages/login/login2.html'));
});

app.get('/usuario', (req, res) => {
   res.sendFile(path.join(__dirname, 'pages/Usuario/Usuario.html'));
});


app.get('/minhasPublicacoes', verificarAutenticacao, async (req, res) => {
    const userId = req.session.usuario_id;

    try {
        const publicacoesUsuario = await buscarPublicacoesDoUsuario(userId);

        // Enviar arquivo HTML estático
        res.sendFile(path.join(__dirname, 'pages/usuarioPublicacao/minhasPublicacoes.html'));
    } catch (error) {
        console.error('Erro ao carregar publicações do usuário:', error);
        res.status(500).send('Erro ao carregar publicações do usuário');
    }
});


// Função para buscar publicações do usuário
async function buscarPublicacoesDoUsuario(userId) {
    try {
        const query = 'SELECT p.ID_Publicação, p.Título, p.Imagem, p.Data_Publicação, u.Nome AS Autor FROM publicação p JOIN usuário u ON p.ID_Usuário = u.ID_Usuário WHERE p.ID_Usuário = ? ORDER BY p.Data_Publicação DESC';
        const [resultados] = await conexao.promise().query(query, [userId]);
        return resultados;
    } catch (error) {
        console.error('Erro ao buscar publicações do usuário:', error);
        throw error;
    }
}


app.get('/api/publicacoes', async (req, res) => {
    const idUsuario = req.session.usuario_id; // Obtém o ID do usuário autenticado da sessão

    const query = 'SELECT * FROM publicação WHERE ID_usuário = ? ORDER BY Data_Publicação DESC';
    conexao.execute(query, [idUsuario], (error, results, fields) => {
        if (error) {
            console.error('Erro ao obter publicações do usuário:', error);
            res.status(500).send('Erro ao obter publicações do usuário');
            return;
        }
        
        res.json(results);
    });
});

app.get('/comentarios/:id_publicacao', (req, res) => {
    const id_publicacao = req.params.id_publicacao;
    const query = `
        SELECT u.Nome AS Usuario, c.Comentario, c.Data_Comentário 
        FROM comentário c
        JOIN usuário u ON c.ID_Usuário = u.ID_Usuário
        WHERE c.ID_Publicação = ?
    `;
    
    conexao.query(query, [id_publicacao], (erro, resultados) => {
        if (erro) {
            console.error('Erro ao buscar comentários: ', erro);
            return res.status(500).send('Erro ao buscar comentários');
        }
        console.log('Comentários encontrados:', resultados); // Log para verificar os resultados
        res.json(resultados);
    });
});




app.get('/perfil', (req, res) => {
    res.sendFile(path.join(__dirname, 'pages/perfil/perfil.html'));
});


app.get('/administrador', (req, res) => {
    res.sendFile(path.join(__dirname, 'pages/Admin/administrador.html'));
});

app.get('/gerencia', (req, res) => {
    res.sendFile(path.join(__dirname, 'pages/gerenciamento/gerencia.html'));
});

// Rota para listar usuários
app.get('/listar-usuarios', async function(req, res) {
    try {
        // Consulta para obter todos os usuários
        const [results] = await conexao.promise().query('SELECT ID_Usuário, Nome, Email, Bloqueado FROM usuário');
        res.json(results); // Retorna a lista de usuários em formato JSON
    } catch (error) {
        console.error('Erro ao listar usuários:', error);
        res.status(500).send('Erro ao listar usuários.');
    }
});


// Rota para listar publicações de um usuário
app.get('/publicacoes-usuario/:id', async function(req, res) {
    const userId = req.params.id;

    try {
        // Consulta para obter as publicações do usuário
        const [results] = await conexao.promise().query('SELECT * FROM publicação WHERE ID_Usuário = ?', [userId]);
        res.json(results); // Retorna a lista de publicações em formato JSON
    } catch (error) {
        console.error('Erro ao listar publicações:', error);
        res.status(500).send('Erro ao listar publicações.');
    }
});


app.get('/denuncias', (req, res) => {
    res.sendFile(path.join(__dirname, 'pages/denuncias/denuncias.html'));
});

// Rota para listar denúncias
app.get('/listar-denuncias', async (req, res) => {
    try {
        const [denuncias] = await conexao.promise().query(`
            SELECT d.ID_Denúncia, 
                d.ID_Publicação, 
                d.ID_Usuário AS ID_Denunciado, 
                d.Motivo, 
                d.Data_Denúncia, 
                d.Status, 
                p.Título AS Publicação, 
                u.Nome AS Usuário_Denunciador, 
                pu.Nome AS Autor_Publicação,
                p.Imagem
            FROM denúncia d
            JOIN publicação p ON d.ID_Publicação = p.ID_Publicação
            JOIN usuário u ON d.ID_Usuário = u.ID_Usuário  -- Usuário que fez a denúncia
            JOIN usuário pu ON p.ID_Usuário = pu.ID_Usuário  -- Autor da publicação
            WHERE d.Status != 'Resolvida';

        `);
        console.log('Denúncias:', denuncias); // Adicione este log
        res.json(denuncias);
    } catch (error) {
        console.error('Erro ao listar denúncias:', error);
        res.status(500).send('Erro ao listar denúncias.');
    }
});

app.post('/alterar-status', (req, res) => {
    const { id, status } = req.body;

    // Verifique se os dados foram recebidos corretamente
    console.log(`ID da Denúncia: ${id}, Novo Status: ${status}`);

    // Execute a lógica para atualizar o status no banco de dados
    const sql = 'UPDATE denúncia SET Status = ? WHERE ID_Denúncia = ?';
    conexao.query(sql, [status, id], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Status alterado com sucesso!' });
    });
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

app.post('/atualizar-foto-perfil', upload.single('fotoPerfil'), (req, res) => {
    const id_usuario = req.session.usuario_id;
    if (!id_usuario) {
        return res.status(401).json({ mensagem: 'Usuário não autenticado' });
    }

    if (!req.file) {
        return res.status(400).json({ mensagem: 'Nenhuma foto enviada' });
    }

    const foto_perfil = req.file.filename; // Nome do arquivo salvo no servidor

    // Atualiza o caminho da foto no banco de dados
    const updateQuery = 'UPDATE usuário SET foto_perfil = ? WHERE ID_Usuário = ?';
    conexao.query(updateQuery, [foto_perfil, id_usuario], (err, resultados) => {
        if (err) {
            console.error('Erro ao atualizar foto de perfil:', err);
            return res.status(500).json({ mensagem: 'Erro ao atualizar foto de perfil' });
        }

        // Redireciona para o perfil após a atualização
        res.redirect('/perfil');
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
            return res.status(400).json({ success: false, message: `Nenhum registro atualizado para o token: ${token}` });
        }

        res.status(200).json({ success: true });

    } catch (erro) {
        console.error('Erro ao completar cadastro: ', erro);
        res.status(500).json({ success: false, message: 'Erro ao completar cadastro' });
    }
});

app.post('/excluir-conta', async (req, res) => {
    const id_usuario = req.session.usuario_id;

    if (!id_usuario) {
        res.status(401).send('Usuário não autenticado');
        return;
    }

    const connection = conexao.promise();
    const deleteCommentsQuery = `DELETE FROM comentário WHERE ID_Usuário = ?`;
    const deletePublicationsQuery = `DELETE FROM publicação WHERE ID_Usuário = ?`;
    const deleteUserQuery = `DELETE FROM usuário WHERE ID_Usuário = ?`;

    try {
        await connection.query('START TRANSACTION');
        await connection.query(deleteCommentsQuery, [id_usuario]);
        await connection.query(deletePublicationsQuery, [id_usuario]);
        await connection.query(deleteUserQuery, [id_usuario]);
        await connection.query('COMMIT');

        // Limpa a sessão após excluir a conta
        req.session.destroy((err) => {
            if (err) {
                console.error('Erro ao destruir sessão após excluir conta:', err);
                res.status(500).send('Erro ao excluir conta');
            } else {
                res.status(200).send('Conta excluída com sucesso!');
            }
        });
    } catch (error) {
        await connection.query('ROLLBACK');
        console.error('Erro ao excluir conta e dados relacionados: ', error);
        res.status(500).send('Erro ao excluir conta');
    }
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

        // Verificar se o email pertence a um administrador
        const [adminResults] = await conexao.promise().query('SELECT * FROM administrador WHERE Email = ?', [email.trim()]);
        if (adminResults.length > 0) {
            const admin = adminResults[0];
            console.log('Administrador encontrado:', admin); // Verifica o administrador encontrado

            // Comparar a senha diretamente, sem criptografia
            if (password === admin.Senha) {
                req.session.admin_id = admin.ID_Administrador;
                console.log('ID do administrador na sessão:', req.session.admin_id); // Verifica se o ID do administrador está sendo armazenado corretamente
                return res.redirect('/gerencia'); // Redireciona para o painel do administrador
            } else {
                console.log('Senha incorreta para administrador'); // Adiciona log para senha incorreta
                return res.status(401).send('Credenciais inválidas: Senha incorreta.');
            }
        }

        // Se não for um administrador, verificar como um usuário comum
        const [userResults] = await conexao.promise().query('SELECT * FROM usuário WHERE Email = ?', [email.trim()]);
        if (userResults.length > 0) {
            const usuario = userResults[0];
            console.log('Usuário encontrado:', usuario); // Verifica o usuário encontrado

            // Comparar a senha usando bcrypt
            const senhaValida = await bcrypt.compare(password, usuario.Senha);
            console.log('Senha válida para usuário:', senhaValida); // Verifica a comparação de senha

            if (senhaValida) {
                req.session.usuario_id = usuario.ID_Usuário;
                console.log('ID do usuário na sessão:', req.session.usuario_id); // Verifica se o ID do usuário está sendo armazenado corretamente
                return res.redirect('/main'); // Redireciona para a página principal do usuário
            } else {
                console.log('Senha incorreta para usuário'); // Adiciona log para senha incorreta
                return res.status(401).send('Credenciais inválidas: Senha incorreta.');
            }
        }

        console.log('Email não encontrado para administrador ou usuário'); // Adiciona log para email não encontrado
        res.status(401).send('Credenciais inválidas: Email não encontrado.');
    } catch (error) {
        console.error('Erro ao verificar credenciais:', error);
        res.status(500).send('Erro ao processar o login.');
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Erro ao encerrar a sessão');
        }
        res.clearCookie('connect.sid'); // Limpa o cookie da sessão
        res.status(200).send('Logout realizado com sucesso');
    });
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
            return res.redirect('/main?error=parâmetros inválidos');
        }

        const inserePublicacaoQuery = 'INSERT INTO publicação (ID_Usuário, Título, Imagem, Data_Publicação, Status) VALUES (?, ?, ?, NOW(), "Ativa")';
        const values = [id_usuario, titulo, imagem];

        conexao.query(inserePublicacaoQuery, values, (erro, resultados) => {
            if (erro) {
                console.error('Erro ao publicar conteúdo: ', erro);
                return res.status(500).send('Erro ao publicar conteúdo');
            }

            console.log('Publicação criada com sucesso!');
            res.redirect('/main');
        });
    } catch (erro) {
        console.error('Erro ao processar requisição:', erro);
        res.status(500).send('Erro ao processar requisição');
    }
});

// Rota para visualizar publicações
app.get('/publicacoes', verificarAutenticacao, async (req, res) => {
    try {
        const query = `
            SELECT p.ID_Publicação, p.Título, p.Imagem, p.Data_Publicação, u.Nome AS Autor, u.Foto_Perfil
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


// Rotas para editar dados do usuário
app.post('/editar-nome', (req, res) => {
    const { nome } = req.body;
    const id_usuario = req.session.usuario_id;

    if (!id_usuario) {
        return res.status(401).send('Usuário não autenticado');
    }

    // Atualiza o nome do usuário na tabela 'usuário'
    const updateQuery = 'UPDATE usuário SET Nome = ? WHERE ID_Usuário = ?';
    conexao.execute(updateQuery, [nome, id_usuario], (err, resultados) => {
        if (err) {
            console.error('Erro ao editar nome:', err);
            return res.status(500).send('Erro ao editar nome');
        }

        if (resultados.affectedRows === 1) {
            res.redirect('/perfil');
        } else {
            res.status(500).send('Erro ao atualizar nome');
        }
    });
});

app.post('/editar-email', (req, res) => {
    const { email } = req.body;
    const id_usuario = req.session.usuario_id;

    if (!id_usuario) {
        return res.status(401).send('Usuário não autenticado');
    }

    // Atualiza o email do usuário na tabela 'usuário'
    const updateQuery = 'UPDATE usuário SET Email = ? WHERE ID_Usuário = ?';
    conexao.execute(updateQuery, [email, id_usuario], (err, resultados) => {
        if (err) {
            console.error('Erro ao editar email:', err);
            return res.status(500).send('Erro ao editar email');
        }

        if (resultados.affectedRows === 1) {
            res.redirect('/perfil');
        } else {
            res.status(500).send('Erro ao atualizar email');
        }
    });
});

app.post('/editar-senha', async (req, res) => {
    const { senhaAtual, novaSenha } = req.body;
    const id_usuario = req.session.usuario_id;

    if (!id_usuario) {
        return res.status(401).json({ error: 'Usuário não autenticado' });
    }

    // Busca o usuário e a senha atual no banco de dados
    const selectQuery = 'SELECT Senha FROM usuário WHERE ID_Usuário = ?';
    conexao.execute(selectQuery, [id_usuario], async (err, resultados) => {
        if (err) {
            console.error('Erro ao buscar usuário:', err);
            return res.status(500).json({ error: 'Erro ao buscar usuário' });
        }

        if (resultados.length === 0) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        const senhaHash = resultados[0].Senha;

        // Verifica se a senha atual está correta
        const senhaValida = await bcrypt.compare(senhaAtual, senhaHash);
        if (!senhaValida) {
            return res.status(401).json({ error: 'Senha atual incorreta' });
        }

        // Gera o hash da nova senha
        const novaSenhaHash = await bcrypt.hash(novaSenha, 10);

        // Atualiza a senha do usuário no banco de dados
        const updateQuery = 'UPDATE usuário SET Senha = ? WHERE ID_Usuário = ?';
        conexao.execute(updateQuery, [novaSenhaHash, id_usuario], (err, resultados) => {
            if (err) {
                console.error('Erro ao editar senha:', err);
                return res.status(500).json({ error: 'Erro ao editar senha' });
            }

            if (resultados.affectedRows === 1) {
                res.status(200).json({ success: 'Senha alterada com sucesso' });
            } else {
                res.status(500).json({ error: 'Erro ao atualizar senha' });
            }
        });
    });
});

//função da pagina minhas publicações

app.post('/editar-titulo', async (req, res) => {
    const { id, novoTitulo } = req.body;
    try {
        const query = `UPDATE publicação SET Título = ? WHERE ID_Publicação = ?`;
        await conexao.promise().query(query, [novoTitulo, id]);
        res.json({ success: true });
    } catch (error) {
        console.error('Erro ao atualizar título:', error);
        res.json({ success: false });
    }
});

app.post('/editar-imagem', upload.single('novaImagem'), async (req, res) => {
    const { id } = req.body;

    if (!req.file) {
        return res.status(400).json({ mensagem: 'Nenhuma imagem foi enviada.' });
    }

    const novaImagem = req.file.filename;

    try {
        const query = `UPDATE publicação SET Imagem = ? WHERE ID_Publicação = ?`;
        await conexao.promise().query(query, [novaImagem, id]);
        res.json({ success: true });
    } catch (error) {
        console.error('Erro ao atualizar imagem:', error);
        res.json({ success: false, mensagem: 'Erro ao atualizar imagem.' });
    }
});


app.post('/excluir-publicacao', async (req, res) => {
    const { id } = req.body;
    const connection = conexao.promise();
    const deleteCommentsQuery = `DELETE FROM comentário WHERE ID_Publicação = ?`;
    const deletePublicationQuery = `DELETE FROM publicação WHERE ID_Publicação = ?`;

    try {
        await connection.query('START TRANSACTION');
        await connection.query(deleteCommentsQuery, [id]);
        await connection.query(deletePublicationQuery, [id]);
        await connection.query('COMMIT');
        res.json({ success: true });
    } catch (error) {
        await connection.query('ROLLBACK');
        console.error('Erro ao excluir publicação e comentários:', error);
        res.json({ success: false });
    }
});




// Adicionar comentário
// app.post('/comentar', async (req, res) => {
//     const { id_publicacao, comentario } = req.body;
//     const id_usuario = req.session.usuario_id;

//     if (!id_publicacao || !id_usuario || !comentario) {
//         return res.status(400).send('Valores não podem ser nulos');
//     }

//     try {
//         await conexao.query('INSERT INTO comentário (ID_Publicação, ID_Usuário, Comentário, Data_Comentário) VALUES (?, ?, ?, NOW())', [id_publicacao, id_usuario, comentario]);
//         res.status(201).send('Comentário adicionado com sucesso');
//     } catch (error) {
//         console.error('Erro ao adicionar comentário:', error);
//         res.status(500).send('Erro ao adicionar comentário');
//     }
// });

app.post('/comentar', async (req, res) => {
    const { id_publicacao, comentario } = req.body;
    const id_usuario = req.session.usuario_id;

    if (!id_publicacao || !comentario || !id_usuario) {
        return res.status(400).json({ error: 'ID da publicação, comentário e ID do usuário são obrigatórios.' });
    }

    try {
        await conexao.promise().query(
            'INSERT INTO comentário (ID_Publicação, ID_Usuário, Comentario, Data_Comentário) VALUES (?, ?, ?, NOW())',
            [id_publicacao, id_usuario, comentario]
        );
        res.status(201).json({ message: 'Comentário adicionado com sucesso!' });
    } catch (error) {
        console.error('Erro ao adicionar comentário:', error);
        res.status(500).json({ error: 'Erro ao adicionar comentário' });
    }
});


app.post('/denunciar', verificarAutenticacao, (req, res) => {
    const { id_publicacao, id_usuario, motivo } = req.body;
    const dataDenuncia = new Date();

    const query = 'INSERT INTO denúncia (ID_Publicação, ID_Usuário, Motivo, Data_Denúncia) VALUES (?, ?, ?, ?)';
    conexao.query(query, [id_publicacao, id_usuario, motivo, dataDenuncia], (erro, resultados) => {
        if (erro) {
            console.error('Erro ao registrar denúncia:', erro);
            return res.status(500).send('Erro ao registrar denúncia');
        }
        res.send('Denúncia registrada com sucesso');
    });
});

app.post('/bloquear-usuario', (req, res) => {
    const { idUsuario, acao } = req.body;
    const novoEstado = acao === 'bloquear' ? 1 : 0;
    const sql = 'UPDATE usuário SET Bloqueado = ? WHERE ID_Usuário = ?';

    conexao.query(sql, [novoEstado, idUsuario], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Erro ao atualizar o estado de bloqueio do usuário' });
        }
        res.json({ success: true, message: `Usuário ${acao} com sucesso`, novoEstado: novoEstado });
    });
});

// Desbloquear usuário
app.post('/desbloquear-usuario', (req, res) => {
    const idUsuario = req.body.idUsuario;
    const sql = `UPDATE usuário SET Bloqueado = 0 WHERE ID_Usuário = ?`;

    conexao.query(sql, [idUsuario], (err, result) => {
        if (err) {
            return res.json({ success: false, message: 'Erro ao desbloquear usuário' });
        }
        res.json({ success: true });
    });
});

// Verificar status do usuário
app.get('/status-usuario/:id', (req, res) => {
    const idUsuario = req.params.id;
    const sql = `SELECT Bloqueado FROM usuário WHERE ID_Usuário = ?`;

    conexao.query(sql, [idUsuario], (err, result) => {
        if (err) {
            return res.json({ success: false, message: 'Erro ao verificar status do usuário' });
        }
        res.json({ bloqueado: result[0].Bloqueado === 1 });
    });
});


app.listen(8081, function() {
    console.log("Servidor Rodando na url http://localhost:8081");
});   