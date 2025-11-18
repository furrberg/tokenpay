package main

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func dbAddUser(db *sql.DB, user *User) error {
	privateKeyBytes := crypto.FromECDSA(user.privateKey)

	_, err := db.Exec("INSERT INTO users (userid, balance, eth_address, private_key) VALUES ($1, $2, $3, $4)", user.UserID, user.Balance, user.EthAddress.Hex(),
		privateKeyBytes)
	if err != nil {
		return fmt.Errorf("addAlbum: %v", err)
	}
	return nil
}

func dbUpdateBalance(db *sql.DB, user *User) error {
	_, err := db.Exec("UPDATE users SET balance = $1 WHERE userid = $2", user.Balance, user.UserID)
	if err != nil {
		return err
	}
	return nil
}

func dbGetUser(db *sql.DB, userID int) (*User, error) {
	var user User
	var privateKeyBytes []byte
	var addressHex string
	var err error

	row := db.QueryRow("SELECT * FROM users WHERE userid=$1", userID)
	if row.Scan(&user.UserID, &user.Balance, &addressHex, &privateKeyBytes) != nil {
		if err = sql.ErrNoRows; err != nil {
			return nil, err
		}
		return nil, errors.New("user not found")
	}
	user.EthAddress = common.HexToAddress(addressHex)
	user.privateKey, err = crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func dbDeleteUser(db *sql.DB, userID int) error {
	_, err := db.Exec("DELETE FROM users WHERE userid=$1", userID)
	if err != nil {
		return err
	}
	return nil
}

func dbUserIterator(db *sql.DB) ([]*User, error) {
	users := []*User{}
	rows, err := db.Query("SELECT * FROM users")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var privateKeyBytes []byte
		user := &User{}
		addressHex := ""
		err = rows.Scan(&user.UserID, &user.Balance, &addressHex, &privateKeyBytes)
		if err != nil {
			return nil, err
		}
		user.EthAddress = common.HexToAddress(addressHex)
		user.privateKey, err = crypto.ToECDSA(privateKeyBytes)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}
