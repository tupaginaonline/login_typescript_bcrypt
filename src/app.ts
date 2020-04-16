import express, {Application} from 'express';
import morgan from 'morgan';
import session from 'express-session';
import bcrypt from 'bcrypt';
import { v4 as uuid } from 'uuid';
import passport from 'passport';
import { Strategy as LocalStrategy} from 'passport-local';

//console.log(express);
//Interfaces

interface IUser{
	id:string;
	email:string;
	password:string;
}

let users:IUser[]= [];

// Initialization

const app:Application = express();

//Middlewares

app.use(morgan('dev'));
app.use(express.json());

app.use(session({
	secret:"mi app",
	resave: false,
	saveUninitialized:false
}));

const authenticateUser = async (email:string, password:string, done:Function) => {
	
	   const user:IUser | undefined = users.find( user => user.email===email);
	   
	   if (user===undefined){
		   console.log("Not find the user"); 
		   return done(null, false);
		}
	   
	   try{
		   if(await bcrypt.compare(password,user.password))
		   {
			   done(null, user);
			   console.log("Success login"); 
		   }else{
			   done(null, false); 
			   console.log("Not allowed"); 
		   }
	   }catch(e){
		  console.log(e); 
	   }
	
};


passport.use(new LocalStrategy({
 usernameField: 'email'	
}, authenticateUser));

passport.serializeUser( (user:IUser, done) => {
	done(null,user.id)
});

passport.deserializeUser( (id, done) => {
	const user:IUser | undefined = users.find( user => user.id === id )
	done(null,user)
});


app.use(passport.initialize());
app.use(passport.session());

const auth = (req:express.Request, res: express.Response, next:Function) => {
	
	if(req.isAuthenticated())
	{
		return next();
	}
	res.status(401).send('Not Allowed...');
	
};


// Routes
app.get('/', (req, res) =>{
	res.status(200).send('Welcome to mi api auth with passport and bcrypt');
});


app.get('/login', (req, res) => {
	res.send('login ...');
});

app.post('/login', passport.authenticate("local",{
	 
	 successRedirect: "/",
	 failureRedirect:"/login"
	
}));

app.get('/users', auth, (req:any , res:express.Response) => {
	console.log(typeof(req));
	res.json(req.user.email);
});

app.post('/register', async (req,res) =>{
	
	const { email, password } = req.body;
	
	try{
		const salt = await bcrypt.genSalt();
		const hashedPassword = await bcrypt.hash(password , salt);
		
		const newUser:IUser = {
			id:uuid(),
			email,
			password:hashedPassword
		};
		
		//users.push(newUser);
		
		users = [...users,newUser];
		
		console.log(users);
		
		res.status(201).send('Success');
		
	
	}catch{
		res.status(500).send('Error');
	}
	
	
});


export default app;