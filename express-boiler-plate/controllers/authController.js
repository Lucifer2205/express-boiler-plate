const usersDB = {
    users:require('../model/users.json'),
    setUsers: function(data) {this.users = data}
}

const jwt = require('jsonwebtoken');
const fsPromises = require('fs').promises;
const path = require('path');
const bcrypt = require('bcrypt');

const handleLogin = async (res,req) => {
    const { user, pwd } = req.body;
    if(!user || !pwd ) return res.status(400).json({'message':'UserName and Password are required.'});
    const foundUser = usersDB.users.find(person => person.username === user);

    if(!foundUser) return res.sendStatus(401);//unauthorized

    //evaluating password
    const match = await bcrypt.compare(pwd,foundUser.password);

    if(match){
        const roles = Object.values(foundUser.roles);

        //create jwt and refresh token here
        const accessToken = jwt.sign(
            {
                "UserInfo":{
                    "username": foundUser.username,
                    "roles":roles
                }
            },
            process.env.ACCESS_TOKEN_SECRET,
            {expiresIn:'1hr'}
        );

        const refreshToken = jwt.sign(
            {"username":foundUser.username},
            process.env.REFRESH_TOKEN_SECRET,
            {expiresIn:'1d'}
        );
        const otherUsers = usersDB.users.filter(person => person.username !== foundUser.username);
        
        //saving refreshtoken with current user
        const currentUser = {...foundUser,refreshToken}

        usersDB.setUsers([...otherUsers, currentUser]);

        await fsPromises.writeFile(path.join(__dirname,'..','model','users.json'),JSON.stringify(usersDB.users)
        );
        res.cookie('jwt', refreshToken, {
            httpOnly:true, sameSite: 'None',secure:true,maxAge:24*60*60*1000
        });
        res.json({ accessToken,roles });
    } else {
        res.sendStatus(401);
    }
}

module.exports = { handleLogin };