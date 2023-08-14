const ClientError = require("../../exceptions/ClientError");

class AuthenticationsHandler {
    constructor(authenticationsService, userService, tokenManager, validator){
        this._authenticationsService = authenticationsService;
        this._usersService = userService;
        this._tokenManager = tokenManager;
        this._validator = validator;

        this.postAuthenticationHandler = this.postAuthenticationHandler.bind(this);
        this.putAuthenticationHandler = this.putAuthenticationHandler.bind(this);
        this.deleteAuthenticationHandler = this.deleteAuthenticationHandler.bind(this);
    }

    async postAuthenticationHandler(request, res){
        try {
            this._validator.validatePostAuthenticationPayload(request.payload); //verifikasi payload

            const {username, password} = request.payload; //menadapatkan nilai dari payload
            const id = await this._usersService.verifyUserCredential(username, password); 
            //Karena fungsi verifyUserCredential mengembalikan nilai id dari user, maka tampung nilai tersebut pada variabel id

            const accessToken = this._tokenManager.generateAccessToken({ id });
            const refreshToken = this._tokenManager.generateRefreshToken({ id });

            await this._authenticationsService.addRefreshToken(refreshToken);

            const response = res.response({
                status: 'success',
                message: 'Authentication berhasil ditambahkan',
                data: {
                    accessToken,
                    refreshToken,
                },
            });
            response.code(201);
            return response;
        } catch (error) {
            if (error instanceof ClientError) {
                const response = res.response({
                  status: 'fail',
                  message: error.message,
                });
                response.code(error.statusCode);
                return response;
              }
         
              // Server ERROR!
              const response = res.response({
                status: 'error',
                message: 'Maaf, terjadi kegagalan pada server kami.',
              });
              response.code(500);
              console.error(error);
              return response;
        }
    }

    async putAuthenticationHandler(request, res){
        try {
          this._validator.validatePutAuthenticationPayload(request.payload);
 
          const { refreshToken } = request.payload;
          await this._authenticationsService.verifyRefreshToken(refreshToken);
          const { id } = this._tokenManager.verifyRefreshToken(refreshToken);
    
          const accessToken = this._tokenManager.generateAccessToken({ id });
          return {
            status: 'success',
            message: 'Access Token berhasil diperbarui',
            data: {
              accessToken,
            },
          };
        } catch (error) {
            if (error instanceof ClientError) {
                const response = res.response({
                  status: 'fail',
                  message: error.message,
                });
                response.code(error.statusCode);
                return response;
              }
         
              // Server ERROR!
              const response = res.response({
                status: 'error',
                message: 'Maaf, terjadi kegagalan pada server kami.',
              });
              response.code(500);
              console.error(error);
              return response;
            
        }
    }

    async deleteAuthenticationHandler(request, res){
      try {
        this._validator.validateDeleteAuthenticationPayload(request.payload);
        const { refreshToken } = request.payload;
        await this._authenticationsService.verifyRefreshToken(refreshToken);
        await this._authenticationsService.deleteRefreshToken(refreshToken);

        return {
          status: 'success',
          message: 'Refresh token berhasil dihapus',
        };
      } catch (error) {
        if (error instanceof ClientError) {
          const response = res.response({
            status: 'fail',
            message: error.message,
          });
          response.code(error.statusCode);
          return response;
        }
   
        // Server ERROR!
        const response = res.response({
          status: 'error',
          message: 'Maaf, terjadi kegagalan pada server kami.',
        });
        response.code(500);
        console.error(error);
        return response;
      }
    }
}
module.exports = AuthenticationsHandler;