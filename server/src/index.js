const http = require('http')
const express = require('express')
const cors = require('cors')
require('./dbMongo/mongoose')
const router = require('./router')
const controller = require('./socketInit')
const handlerError = require('./handlerError/handler')

const authRouter = require("./router/authRouter");

const PORT = process.env.PORT || 5000
const app = express()

app.use(cors())
app.use(express.json())
app.use('/public', express.static('public'))
app.use('/auth', authRouter);
app.use(router)
app.use(handlerError)

const server = http.createServer(app)
server.listen(PORT, () => console.log(`Example app listening on port ${PORT}!`))
controller.createConnection(server)
