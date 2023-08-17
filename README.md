# Тестовое задание по graphql
## Запуск и использование
1. `npm install`
2. Создать файл `.env` со следующими переменными:
   - `JWT_SECRET`
   - `DATABASE_URL`
3. Инициализировать базу данных в соответствии с `prisma/schema.prisma`
4. `npm start`
5. Открыть в браузере `localhost:4001`
6. Для выполнения запросов, кроме `login` и `register` небходимо иметь `header` `Authorization` вида `Bearer <token>`, где `<token>` возвращает метод `login`