package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/furrberg/chainctl/qweezxc"
	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
)

// global variables that are used to store data from server
var (
	userID        int
	recipientID   int
	ethAddress    string
	amount        int
	url           string
	usersSnapshot Users
	userVisible   User
)

//

// User defines scope of attributes that each user is assigned.
type User struct {
	UserID     int
	Balance    int
	EthAddress common.Address
	privateKey *ecdsa.PrivateKey
	AuthData   map[string]string
}

// Users map of all existing users
type Users map[int]*User

var rootCmd = &cobra.Command{
	Use:   "tokenpay",
	Short: "tokenpay is a tool for interacting with tokenpay",
}

// createUserCmd creates new user struct instance with 0 balance and adds it to the map of all users
var createUserCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a user",
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := http.Get("localhost:8080/usernew")
		if err != nil {
			return err
		}
		err = json.NewDecoder(resp.Body).Decode(&userVisible)
		if err != nil {
			return err
		}
		fmt.Printf("User registered with ID %d and Address %d\n", userVisible.UserID, userVisible.EthAddress)
		return nil
	},
}

// transferCmd Used to transfer funds from one user id to another
var transferCmd = &cobra.Command{
	Use:   "transfer",
	Short: "Transfer tokens",
	RunE:  transfer,
}

func transfer(cmd *cobra.Command, args []string) error {
	url = "http://localhost:8080/" + strconv.Itoa(userID) + "/transfer" + strconv.Itoa(amount) + strconv.Itoa(recipientID)
	bytesObj := []byte(`{"key":"value"}`)
	body := bytes.NewBuffer(bytesObj)
	_, err := http.Post(url, "text/plain", body)
	if err != nil {
		return err
	}
	fmt.Printf("%v was succesfuly sent to %v\n", amount, recipientID)

	return nil
}

var withdrawCmd = &cobra.Command{
	Use:   "withdraw",
	Short: "Withdraw tokens",
	RunE:  withdraw,
}

func withdraw(cmd *cobra.Command, args []string) error {
	url = "http://localhost:8080/" + strconv.Itoa(userID) + "/withdraw" + strconv.Itoa(amount) + ethAddress
	bytesObj := []byte(`{"key":"value"}`)
	body := bytes.NewBuffer(bytesObj)
	_, err := http.Post(url, "text/plain", body)
	if err != nil {
		return err
	}
	fmt.Printf("%v was succesfuly withdrawn to %v\n", amount, ethAddress)

	return nil
}

var getDataCmd = &cobra.Command{
	Use:   "get",
	Short: "Get data",
	RunE: func(cmd *cobra.Command, args []string) error {
		url = "http://localhost:8080/" + strconv.Itoa(userID) + "/get-data"
		resp, err := http.Get(url)
		if err != nil {
			return err
		}
		err = json.NewDecoder(resp.Body).Decode(&userVisible)
		if err != nil {
			return err
		}

		fmt.Println(userVisible.UserID, userVisible.EthAddress, userVisible.Balance)

		return nil
	},
}

var checkBalanceCmd = &cobra.Command{
	Use:   "checkbalance",
	Short: "Check balance",
	RunE: func(cmd *cobra.Command, args []string) error {
		url = "http://localhost:8080/" + strconv.Itoa(userID) + "/check-balance"
		resp, err := http.Get(url)
		if err != nil {
			return err
		}
		err = json.NewDecoder(resp.Body).Decode(&userVisible)
		if err != nil {
			return err
		}

		fmt.Printf("Your current balance is %v\n", userVisible.Balance)
		return nil
	},
}

func listener() {
	users := make(Users)
	router := mux.NewRouter()

	// router Endpoints
	router.HandleFunc("/users", func(writer http.ResponseWriter, request *http.Request) {
		json.NewEncoder(writer).Encode(users)
	}).Methods("GET")
	router.HandleFunc("/usernew", func(writer http.ResponseWriter, request *http.Request) {
		key, err := crypto.GenerateKey()
		if err != nil {
			return
		}

		user := User{
			UserID:     rand.Int(),
			Balance:    0,
			EthAddress: crypto.PubkeyToAddress(key.PublicKey),
			privateKey: key,
		}

		userVisible = User{
			UserID:     user.UserID,
			Balance:    user.Balance,
			EthAddress: user.EthAddress,
		}

		users[user.UserID] = &user
		usersSnapshot = users
		err = json.NewEncoder(writer).Encode(userVisible)
		if err != nil {
			return
		}
	}).Methods("GET")
	router.HandleFunc("/users/{id}", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		userID, err := strconv.Atoi(params["id"])
		if err != nil {
			_, err2 := fmt.Fprintln(writer, err)
			if err2 != nil {
				return
			}
		}
		for _, user := range users {
			if user.UserID == userID {
				err = json.NewEncoder(writer).Encode(users[userID])
				if err != nil {
					return
				}
			}
		}
	}).Methods("GET")
	router.HandleFunc("/users/{id}/check-balance", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		userID, err := strconv.Atoi(params["id"])
		if err != nil {
			_, err2 := fmt.Fprintln(writer, err)
			if err2 != nil {
				return
			}
		}
		for _, user := range users {
			if user.UserID == userID {
				err = json.NewEncoder(writer).Encode(users[userID].Balance)
				if err != nil {
					return
				}
			}
		}
	}).Methods("GET")
	router.HandleFunc("/users/{id}/deposit", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		userID, err := strconv.Atoi(params["id"])
		if err != nil {
			_, err2 := fmt.Fprintln(writer, err)
			if err2 != nil {
				return
			}
		}
		for _, user := range users {
			if user.UserID == userID {
				err = json.NewEncoder(writer).Encode(users[userID].EthAddress)
				if err != nil {
					return
				}
			}
		}
	}).Methods("GET")
	router.HandleFunc("/users/{id}/get-userid", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		userID, err := strconv.Atoi(params["id"])
		if err != nil {
			_, err2 := fmt.Fprintln(writer, err)
			if err2 != nil {
				return
			}
		}
		for _, user := range users {
			if user.UserID == userID {
				err = json.NewEncoder(writer).Encode(users[userID].UserID)
				if err != nil {
					return
				}
			}
		}
	}).Methods("GET")
	router.HandleFunc("/users/{id}/get-data", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		userID, err := strconv.Atoi(params["id"])
		if err != nil {
			_, err2 := fmt.Fprintln(writer, err)
			if err2 != nil {
				return
			}
		}
		for _, user := range users {
			if user.UserID == userID {
				usrData := &User{
					UserID:     userID,
					Balance:    users[userID].Balance,
					EthAddress: users[userID].EthAddress,
				}
				err = json.NewEncoder(writer).Encode(usrData)
				if err != nil {
					return
				}
			}
		}
	}).Methods("GET")
	router.HandleFunc("/users/{id}", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		userID, err := strconv.Atoi(params["id"])
		if err != nil {
			_, err2 := fmt.Fprintln(writer, err)
			if err2 != nil {
				return
			}
		}
		for _, user := range users {
			if user.UserID == userID {
				_, ok := users[userID]
				if ok {
					delete(users, userID)
				}
			}
		}
		usersSnapshot = users
	}).Methods("DELETE")
	// http transfer function that allows to transfer available funds to other used id balance
	router.HandleFunc("/users/{id}/transfer{amount}{recipientid}", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		userID, err := strconv.Atoi(params["id"])
		amount, err := strconv.Atoi(params["amount"])
		recipient, err := strconv.Atoi(params["recipientid"])
		if err != nil {
			_, err2 := fmt.Fprintln(writer, err)
			if err2 != nil {
				return
			}
		}
		for _, user := range users {
			if user.UserID == userID {
				if user.Balance < amount {
					fmt.Fprintln(writer, "Insufficient balance")
				}
				if _, ok := users[recipient]; !ok {
					fmt.Fprintln(writer, "User not found")
				}
				user.Balance -= amount
				users[recipient].Balance += amount
			}
		}
		usersSnapshot = users
	}).Methods("POST")

	router.HandleFunc("/users/{id}/withdraw{amount}{address}", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		userID, err := strconv.Atoi(params["id"])
		if err != nil {
			fmt.Fprintln(writer, err)
		}
		amount, err := strconv.Atoi(params["amount"])
		if err != nil {
			fmt.Fprintln(writer, err)
		}
		recipient := common.HexToAddress(params["address"])

		for _, user := range users {
			if user.UserID == userID {
				if user.Balance < amount {
					fmt.Fprintln(writer, "Insufficient balance")
				}
				user.Balance -= amount

				client, err := ethclient.Dial(url)
				if err != nil {
					fmt.Fprintln(writer, err)
				}

				contractAddress := common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")

				instance, err := qweezxc.NewQweezxc(contractAddress, client)
				if err != nil {
					fmt.Fprintln(writer, err)
				}

				chainID, ok := new(big.Int).SetString("31337", 10)
				if !ok {
					fmt.Fprintln(writer, err)
				}

				nonce, err := client.PendingNonceAt(context.Background(), user.EthAddress)
				if err != nil {
					log.Fatal(err)
				}

				gasPrice, err := client.SuggestGasPrice(context.Background())
				if err != nil {
					log.Fatal(err)
				}

				authSpender, err := bind.NewKeyedTransactorWithChainID(user.privateKey, chainID)
				if err != nil {
					fmt.Fprintln(writer, err)
				}
				authSpender.Nonce = big.NewInt(int64(nonce))
				authSpender.Value = big.NewInt(0) // in wei
				authSpender.GasLimit = uint64(0)  // in units
				authSpender.GasPrice = gasPrice

				nonce, err = client.PendingNonceAt(context.Background(), common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"))

				privateKeyOwner, err := crypto.HexToECDSA("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
				if err != nil {
					fmt.Fprintln(writer, err)
				}
				authOwner, err := bind.NewKeyedTransactorWithChainID(privateKeyOwner, chainID)
				if err != nil {
					fmt.Fprintln(writer, err)
				}
				authOwner.Nonce = big.NewInt(int64(nonce))
				authOwner.Value = big.NewInt(0) // in wei
				authOwner.GasLimit = uint64(0)  // in units
				authOwner.GasPrice = gasPrice

				_, err = instance.Approve(authOwner, user.EthAddress, new(big.Int).SetInt64(int64(amount)))
				if err != nil {
					return
				}
				_, err = instance.TransferFrom(authSpender, common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), recipient, new(big.Int).SetInt64(int64(amount)))
				if err != nil {
					return
				}

				fmt.Fprintln(writer, "Withdrawn successfully to %v\n", recipient)
				fmt.Fprintln(writer, "New balance: %v\n", user.Balance)
			}
		}
		usersSnapshot = users
	}).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", router))
}

// autoTransfer transfers tokens from user eth addresses to main address every period
func autoTransfer() {
	client, err := ethclient.Dial(url)
	if err != nil {
		fmt.Errorf(err.Error())
	}

	instance, err := qweezxc.NewQweezxc(common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3"), client)
	if err != nil {
		fmt.Println(err)
	}
	for {
		select {
		case <-time.Tick(10 * time.Second):
			for _, v := range usersSnapshot {
				balance, err := instance.BalanceOf(nil, v.EthAddress)
				if err != nil {
					fmt.Println(err)
				}
				if balance.Int64() > 0 {
					chainID, ok := new(big.Int).SetString("31337", 10)
					if !ok {
						fmt.Println(err)
					}

					nonce, err := client.PendingNonceAt(context.Background(), v.EthAddress)
					if err != nil {
						fmt.Println(err)
					}

					gasPrice, err := client.SuggestGasPrice(context.Background())
					if err != nil {
						fmt.Println(err)
					}

					authOwner, err := bind.NewKeyedTransactorWithChainID(v.privateKey, chainID)
					if err != nil {
						fmt.Println(err)
					}
					authOwner.Nonce = big.NewInt(int64(nonce))
					authOwner.Value = big.NewInt(0) // in wei
					authOwner.GasLimit = uint64(0)  // in units
					authOwner.GasPrice = gasPrice

					_, err = instance.Transfer(authOwner, common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), balance)
					if err != nil {
						return
					}
					fmt.Printf("Transferred %v tokens successfully to main account from %v\n", balance.Int64(), v.EthAddress)
				}
			}
		}
	}
}

func init() {
	rootCmd.AddCommand(createUserCmd)
	rootCmd.AddCommand(transferCmd)
	rootCmd.AddCommand(withdrawCmd)
	rootCmd.AddCommand(getDataCmd)
	rootCmd.AddCommand(checkBalanceCmd)
	transferCmd.Flags().IntVar(&userID, "id", 0, "User ID")
	transferCmd.Flags().IntVarP(&amount, "amount", "a", 1, "Amount to transfer")
	transferCmd.Flags().IntVarP(&recipientID, "recipient", "r", 0, "Recipient ID")
	withdrawCmd.Flags().IntVar(&userID, "id", 0, "User ID")
	withdrawCmd.Flags().StringVar(&ethAddress, "address", "", "Amount to withdraw")
	withdrawCmd.Flags().IntVarP(&amount, "amount", "a", 0, "Amount to withdraw")
	getDataCmd.Flags().IntVar(&userID, "id", 0, "User ID")
	checkBalanceCmd.Flags().IntVar(&userID, "id", 0, "User ID")
	err := transferCmd.MarkFlagRequired("id")
	if err != nil {
		fmt.Println(err)
	}
	err = transferCmd.MarkFlagRequired("amount")
	if err != nil {
		fmt.Println(err)
	}
	err = transferCmd.MarkFlagRequired("recipient")
	if err != nil {
		fmt.Println(err)
	}
	err = withdrawCmd.MarkFlagRequired("id")
	if err != nil {
		fmt.Println(err)
	}
	err = withdrawCmd.MarkFlagRequired("address")
	if err != nil {
		fmt.Println(err)
	}
	err = withdrawCmd.MarkFlagRequired("amount")
	if err != nil {
		fmt.Println(err)
	}
	err = getDataCmd.MarkFlagRequired("id")
	if err != nil {
		fmt.Println(err)
	}
	err = checkBalanceCmd.MarkFlagRequired("id")
	if err != nil {
		fmt.Println(err)
	}
}

func main() {
	wg := new(sync.WaitGroup)
	wg.Go(autoTransfer)
	wg.Go(listener)

	err := rootCmd.Execute()
	if err != nil {
		return
	}
	wg.Wait()
}
