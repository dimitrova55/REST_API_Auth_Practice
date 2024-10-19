import Datastore from "nedb-promises";
import NodeCache from "node-cache";

// Create a database instance
export const usersDB = Datastore.create('./server/db/Users.db');
export const userRefreshTokensDB = Datastore.create('./server/db/UserRefreshTokens.db');
export const userInvalidTokensDB = Datastore.create('./server/db/UserInvalidTokens.db');   // once the user has logout the access token goes to the 'black list'

export const cache = new NodeCache();