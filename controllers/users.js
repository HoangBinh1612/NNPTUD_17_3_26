let userModel = require("../schemas/users");
let bcrypt = require('bcrypt');

module.exports = {
    CreateAnUser: async function (username, password, email, role,
        fullName, avatarUrl, status, loginCount
    ) {
        let newUser = new userModel({
            username: username,
            password: password,
            email: email,
            fullName: fullName,
            avatarUrl: avatarUrl,
            status: status,
            role: role,
            loginCount: loginCount
        })
        await newUser.save();
        return newUser;
    },
    FindUserByUsername: async function (username) {
        return await userModel.findOne({
            isDeleted: false,
            username: username
        })
    },
    CompareLogin: async function (user, password) {
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            await user.save()
            return user;
        }
        user.loginCount++;
        if (user.loginCount == 3) {
            user.lockTime = new Date(Date.now() + 24 * 60 * 60 * 1000);
            user.loginCount = 0;
        }
        await user.save()
        return false;
    },
    GetUserById: async function (id) {
        try {
            let user = await userModel.findOne({
                _id: id,
                isDeleted: false
            })
            return user;
        } catch (error) {
            return false;
        }
    },
    ChangePassword: async function (userId, oldPassword, newPassword) {
        let user = await userModel.findOne({
            _id: userId,
            isDeleted: false
        });
        if (!user) {
            throw new Error("Khong tim thay user");
        }
        let isMatch = bcrypt.compareSync(oldPassword, user.password);
        if (!isMatch) {
            throw new Error("Mat khau cu khong dung");
        }
        user.password = newPassword;
        await user.save();
        return user;
    }
}