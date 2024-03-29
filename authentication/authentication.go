package authentication

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"jwtgo/models"
	"log"
	"net/http"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

func init() {
	filePrivate, err := os.Open("./keys/private.rsa")
	if err != nil {
		log.Fatal("No se encontró la llave privada")
	}
	defer filePrivate.Close()

	privateBytes := new(bytes.Buffer)
	_, err = io.Copy(privateBytes, filePrivate)

	if err != nil {
		log.Fatal("No se encontró la llave privada")
	}

	filePublic, err := os.Open("./keys/public.rsa.pub")
	if err != nil {
		log.Fatal("No se encontró la llave privada")
	}
	defer filePublic.Close()

	publicBytes := new(bytes.Buffer)
	_, err = io.Copy(publicBytes, filePublic)

	if err != nil {
		log.Fatal("No se encontró la llave privada")
	}

	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateBytes.Bytes())

	if err != nil {
		log.Fatal("No se logró realizar el Parse a privateKey")
	}

	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicBytes.Bytes())

	if err != nil {
		log.Fatal("No se logró realizar el Parse a publicKey")
	}
}

// GenerateJWT : Función para generar el JWT
func GenerateJWT(user models.User) string {
	claims := models.Claim{
		User: user,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
			Issuer:    "Tallerde sábado",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	result, err := token.SignedString(privateKey)

	if err != nil {
		log.Fatal("No se logró firmar el JWT")
	}

	return result
}

// Login : Test Login
func Login(w http.ResponseWriter, r *http.Request) {
	var user models.User

	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		fmt.Fprintln(w, "Error al leer el usuario %s", err.Error())
		return
	}

	if user.Name == "hector" && user.Password == "alberto" {
		user.Password = ""
		user.Rol = "admin"

		token := GenerateJWT(user)

		result := models.ResponseToken{token}

		jsonResult, err := json.Marshal(result)

		if err != nil {
			fmt.Fprintln(w, "Error al codificar el toketn %s", err)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResult)
	} else {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Usuario inválido")
	}
}

// ValidateToken : Validación del toketn
func ValidateToken(w http.ResponseWriter, r *http.Request) {
	token, err := request.ParseFromRequestWithClaims(r, request.OAuth2Extractor, &models.Claim{}, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})

	if err != nil {
		switch err.(type) {
		case *jwt.ValidationError:
			vErr := err.(*jwt.ValidationError)
			switch vErr.Errors {
			case jwt.ValidationErrorExpired:
				fmt.Fprintln(w, "Su token ha expirado")
				return
			case jwt.ValidationErrorSignatureInvalid:
				fmt.Fprintln(w, "La firma no es válida")
				return
			default:
				fmt.Fprintln(w, "El token no es válido")
				return
			}
		default:
			fmt.Fprintln(w, "Token no reconocido")
			return
		}
	}

	if token.Valid {
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintln(w, "Bienvenido al sistema")
	} else {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "No tiene permisos")
	}
}
