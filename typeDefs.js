import { gql } from 'apollo-server'


const typeDefs = gql`
    type Query{
        users:[User]
    }

    input UserInput{
        firstName:String!
        lastName:String!
        email:String!
        password:String!
    }
    input UserSigninInput{
        email:String!
        password:String!
    }

    type Token{
        token:String!
    }

    type Mutation{
        signupUser(userNew: UserInput!): User
        signinUser(userSignin:UserSigninInput!):Token
    }

    type User{
        id:ID!
        firstName:String!
        lastName:String!
        email:String!
    }
`

export default typeDefs;