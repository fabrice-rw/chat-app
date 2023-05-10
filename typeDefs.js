import { gql } from 'apollo-server'


const typeDefs = gql`
    type Query{
        users:[User]
        user(id:ID!):User
    }

    input UserInput{
        firstName:String!
        lastName:String!
        email:String!
        password:String!
    }

    type Mutation{
    
    }

    type User{
        id:ID!
        firstName:String!
        lastName:String!
        email:String!
    }
`

export default typeDefs;