import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config()

const connectDb = async () =>{
    try{
        const conn = await mongoose.connect(process.env.MONGO_URL)
        console.log('Connected to the Database')
    }
    catch(error){
        console.error('MONGODB connection error')
    }
}

export default connectDb