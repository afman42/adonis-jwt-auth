import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
import Hash from '@ioc:Adonis/Core/Hash'
import User from 'App/Models/User';
import { schema } from '@ioc:Adonis/Core/Validator'

export default class UsersController {

    async login({ auth,request, response } : HttpContextContract){
        const newUserSchema = schema.create({
            email: schema.string(),
            password: schema.string(),
        })
        const payloadData = await request.validate({
            schema: newUserSchema,
        });

        const user = await User.findByOrFail('email',payloadData.email)
        
        if (!(await Hash.verify(user.password, payloadData.password))) {
            return response.badRequest('Invalid credentials')
          }        
        
        const token = await auth.use('api').generate(user, {
            expiresIn: '30mins'
        })

        return response.json({
            status: 200,
            token
        })
    }

    async fetchProfile({ auth,response }: HttpContextContract) {
        const authUser = await auth.use('api');
        if (authUser.isLoggedIn) {
            return response.json({
                token: authUser.user
            })
        } else {
            return response.badRequest('Invalid credentials')
        }
    }

    async logout({ auth }: HttpContextContract) {
        await auth.use('api').revoke()
        return {
          revoked: true
        }      
    }
}
