import { ApolloServer } from '@apollo/server'
import { startStandaloneServer } from '@apollo/server/standalone'
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcrypt'
import 'dotenv/config'
import { GraphQLError } from 'graphql'
import jwt from 'jsonwebtoken'

const JWT_SECRET = process.env.JWT_SECRET
const SALT_ROUNDS = 10
const EMAIL_REGEXP =
	/(?:[a-z0-9+!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/i
const PASSWORD_REGEXP = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9])(?!.*\s).{8,15}$/
const PASSWORD_MSG =
	'Password must be between 8 to 15 characters which contain at least one lowercase letter, one uppercase letter, one numeric digit, and one special character'
const ACCOUNT_REGEXP = /^\d{16}$/
const ACCOUNT_MSG = 'Account must contain only 16 digits'

const prisma = new PrismaClient()

const typeDefs = `#graphql
  type User {
    id: ID!
    email: String!
    created_at: String!
    accounts: [Account]!
  }

  type Account {
    id: ID!
    currency: Int!
    amount: Float!
    created_at: String!
    user: User!
    name: String!
    status: Int!
  }

  type AuthPayload {
    token: String!
    user: User!
  }

  type AccountPayload {
    account: Account!
  }

  type Query {
    accounts(limit: Int = 10, offset: Int = 0): [Account!]!
  }

  type Mutation {
    login (email: String!, password: String!): AuthPayload!
    register(email: String!, password: String!): AuthPayload!
    createAccount(currency: Int!, amount: Float!, status: Int!, name: String!): AccountPayload!
    changeStatus(id: Int!, status: Int!): AccountPayload!
    deleteAccount(id: Int!): AccountPayload!
  }

`

const checkAuthentication = user => {
	if (user) return
	throw new GraphQLError('You are not authorized to perform this action.', {
		extensions: {
			code: 'FORBIDDEN',
		},
	})
}

const databaseAction = async (action, name) => {
	try {
		return await action()
	} catch (error) {
		throw new GraphQLError(`${name[0].toUpperCase() + name.slice(1)} database action processing error`, {
			extensions: {
				code: 'DATABASE_ERROR',
			},
		})
	}
}

const validate = values => {
	const errors = []
	for (const key in values) {
		const value = values[key]
		if (key === 'email') {
			if (!value.match(EMAIL_REGEXP)) errors.push(key)
		} else if (key === 'password') {
			if (!value.match(PASSWORD_REGEXP)) errors.push({ [key]: PASSWORD_MSG })
		} else if (key === 'account') {
			if (!value.match(ACCOUNT_REGEXP)) errors.push({ [key]: ACCOUNT_MSG })
		} else if (key === 'currency') {
			if (value <= 0) errors.push(key)
		} else if (key === 'status') {
			if (![0, 1].includes(value)) errors.push(key)
		}
	}
	if (errors.length > 0) {
		throw new GraphQLError('Some validations failed.', {
			extensions: {
				code: 'VALIDATION_FAILED',
				errors,
			},
		})
	}
}

const resolvers = {
	Query: {
		accounts: (_, { limit, offset }, { user }) => {
			checkAuthentication(user)
			const accounts = prisma.accounts.findMany({
				where: { user_id: user.id },
				skip: offset,
				take: limit,
				include: { user: true },
			})
			return accounts
		},
	},
	Mutation: {
		async login(_, { email, password }) {
			validate({ email })
			try {
				const user = await prisma.users.findUnique({ where: { email } })
				if (!user) throw new Error('No user with that email')
				const isValid = await bcrypt.compare(password, user.password_hash)
				if (!isValid) throw new Error('Incorrect password')
				const token = jwt.sign({ id: user.id }, JWT_SECRET)
				return { token, user }
			} catch (error) {
				throw new GraphQLError(error.message, {
					extensions: {
						code: 'LOGIN_FAILED',
					},
				})
			}
		},

		async register(_, { email, password }) {
			validate({ email, password })
			const password_hash = await bcrypt.hash(password, SALT_ROUNDS)
			const user = await databaseAction(
				() => prisma.users.create({ data: { email, created_at: new Date(), password_hash } }),
				'create user'
			)
			const token = jwt.sign({ id: user.id }, JWT_SECRET)
			return { token, user }
		},

		async createAccount(_, { currency, amount, status, name }, { user }) {
			checkAuthentication(user)
			validate({ status, currency, account: name })
			const account = await databaseAction(
				() =>
					prisma.accounts.create({
						data: {
							currency,
							amount,
							status,
							name,
							created_at: new Date(),
							user_id: user.id,
						},
					}),
				'create account'
			)
			return { account }
		},

		async changeStatus(_, { id, status }, { user }) {
			checkAuthentication(user)
			validate({ status })
			const account = await databaseAction(
				() =>
					prisma.accounts.update({
						where: {
							id,
							user_id: user.id,
						},
						data: {
							status,
						},
					}),
				'change account status'
			)
			return { account }
		},

		async deleteAccount(_, { id }, { user }) {
			checkAuthentication(user)
			const account = await databaseAction(
				() =>
					prisma.accounts.delete({
						where: {
							id,
							user_id: user.id,
						},
					}),
				'delete account'
			)
			return { account }
		},
	},
}

const server = new ApolloServer({
	typeDefs,
	resolvers,
})

const { url } = await startStandaloneServer(server, {
	listen: { port: 4001 },
	context: async ({ req }) => {
		const token = req.headers.authorization || ''
		let user
		try {
			user = jwt.verify(token.replace('Bearer', '').trim(), JWT_SECRET)
		} catch (e) {
			user = undefined
		}
		return { user }
	},
})

console.log(`🚀  Server ready at: ${url}`)
