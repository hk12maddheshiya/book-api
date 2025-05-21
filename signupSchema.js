import {z} from 'zod';

const schema = z.object({ 
    username: z.string().min(8).max(20),
    password: z.string().min(8).max(20).regex(/[a-z]/, "Password must contain at least one lowercase letter").regex(/[A-Z]/, "Password must contain at least one uppercase letter"),
    name: z.string().min(5).max(30) 
})

export default schema;