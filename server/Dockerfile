FROM node:14.16.1

ARG NODE_ENV="development"

RUN mkdir /server

RUN mkdir -p /var/www/html/images

WORKDIR /server

COPY package*.json ./

RUN npm install -g nodemon\
&& npm install -g sequelize-cli\
&& npm install

COPY . .

EXPOSE 5000

CMD sequelize db:migrate && sequelize db:seed:all && npm start