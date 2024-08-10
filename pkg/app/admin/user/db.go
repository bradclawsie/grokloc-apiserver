package user

import (
	"context"

	"github.com/google/uuid"
	"github.com/grokloc/grokloc-apiserver/pkg/app/audit"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/jackc/pgx/v5"
)

// New returns a new unencrypted User.
// Org is not validated. Use Create for validation.
func New(
	displayName safe.VarChar,
	email safe.VarChar,
	org models.ID,
	password safe.Password,
) (*User, error) {
	apiSecret := models.NewID().String()
	u := &User{
		APISecret:         safe.TrustedVarChar(apiSecret),
		APISecretDigest:   security.EncodedSHA256(apiSecret),
		DisplayName:       displayName,
		DisplayNameDigest: security.EncodedSHA256(displayName.String()),
		Email:             email,
		EmailDigest:       security.EncodedSHA256(email.String()),
		Org:               org,
		Password:          password,
	}
	u.Meta.Role = models.RoleNormal
	u.Meta.Status = models.StatusInactive
	u.ID = models.NewID()
	return u, nil
}

// Encrypt resets APISecret, DisplayName, Email to their encrypted forms.
func (u *User) Encrypt(key []byte, keyVersion uuid.UUID) error {
	if u.encrypted {
		return nil
	}

	encryptedAPISecret, apiSecretErr := security.Encrypt(u.APISecret.String(), key)
	if apiSecretErr != nil {
		return apiSecretErr
	}

	encryptedDisplayName, displayNameErr := security.Encrypt(u.DisplayName.String(), key)
	if displayNameErr != nil {
		return displayNameErr
	}

	encryptedEmail, emailErr := security.Encrypt(u.Email.String(), key)
	if emailErr != nil {
		return emailErr
	}

	u.APISecret = safe.TrustedVarChar(encryptedAPISecret)
	u.DisplayName = safe.TrustedVarChar(encryptedDisplayName)
	u.Email = safe.TrustedVarChar(encryptedEmail)
	u.KeyVersion = keyVersion
	u.encrypted = true

	return nil
}

// Decrypt resets APISecret, DisplayName, Email to their decrypted forms.
func (u *User) Decrypt(versionKey *security.VersionKey) error {
	if !u.encrypted {
		return nil
	}

	key, keyErr := versionKey.Get(u.KeyVersion)
	if keyErr != nil {
		return keyErr
	}

	apiSecret, apiSecretErr := security.Decrypt(u.APISecret.String(), u.APISecretDigest, key)
	if apiSecretErr != nil {
		return apiSecretErr
	}

	displayName, displayNameErr := security.Decrypt(u.DisplayName.String(), u.DisplayNameDigest, key)
	if displayNameErr != nil {
		return displayNameErr
	}

	email, emailErr := security.Decrypt(u.Email.String(), u.EmailDigest, key)
	if emailErr != nil {
		return emailErr
	}

	u.APISecret = safe.TrustedVarChar(apiSecret)
	u.DisplayName = safe.TrustedVarChar(displayName)
	u.Email = safe.TrustedVarChar(email)
	u.encrypted = false

	return nil
}

// Insert a User into the db.
// Mutations to u in this method will not impact caller.
func (u User) Insert(
	ctx context.Context,
	conn *pgx.Conn,
	keyVersion uuid.UUID,
	key []byte,
) error {
	encryptErr := u.Encrypt(key, keyVersion)
	if encryptErr != nil {
		return encryptErr
	}

	const insertQuery = `
      	insert into users
        	(id,
         	api_secret,
         	api_secret_digest,
         	display_name,
         	display_name_digest,
         	email,
         	email_digest,
         	key_version,
         	org,
         	password,
         	role,
         	schema_version,
         	status)
      	values
      	($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      	`

	result, err := conn.Exec(ctx, insertQuery,
		u.ID,
		u.APISecret,
		u.APISecretDigest,
		u.DisplayName,
		u.DisplayNameDigest,
		u.Email,
		u.EmailDigest,
		u.KeyVersion,
		u.Org,
		u.Password,
		u.Meta.Role,
		u.Meta.SchemaVersion,
		u.Meta.Status,
	)
	if err != nil {
		if models.UniqueConstraint(err) {
			return models.ErrConflict
		}
		return err
	}

	inserted := result.RowsAffected()
	if inserted != 1 {
		return models.ErrRowsAffected
	}
	return nil
}

// Create inserts a new org and org owner into the db.
// Performs validation.
func Create(
	ctx context.Context,
	conn *pgx.Conn,
	displayName safe.VarChar,
	email safe.VarChar,
	org models.ID,
	password safe.Password,
	versionKey *security.VersionKey,
) (*User, error) {
	tx, txErr := conn.Begin(ctx)
	if txErr != nil {
		return nil, txErr
	}
	defer tx.Rollback(ctx) // nolint:errcheck

	const readOrgQuery = "select role, status from orgs where id = $1"
	var orgRole models.Role
	var orgStatus models.Status
	selectErr := tx.QueryRow(ctx, readOrgQuery, org).Scan(&orgRole, &orgStatus)
	if selectErr != nil {
		if pgx.ErrNoRows == selectErr {
			return nil, models.ErrNotFound
		}
		return nil, selectErr
	}

	if orgStatus != models.StatusActive {
		return nil, models.ErrRelatedOrg
	}

	u, uErr := New(
		displayName,
		email,
		org,
		password,
	)
	if uErr != nil {
		return nil, uErr
	}
	u.Org = org
	u.Meta.Role = orgRole
	u.Meta.Status = models.StatusUnconfirmed

	keyVersion, key, keyErr := versionKey.GetCurrent()
	if keyErr != nil {
		return nil, keyErr
	}

	insertErr := u.Insert(ctx, tx.Conn(), keyVersion, key)
	if insertErr != nil {
		return nil, insertErr
	}

	uRead, uReadErr := Read(ctx, tx.Conn(), versionKey, u.ID)
	if uReadErr != nil {
		return nil, uReadErr
	}

	auditErr := audit.Insert(ctx, tx.Conn(), audit.UserInsert, "users", u.ID)
	if auditErr != nil {
		return nil, auditErr
	}

	commitErr := tx.Commit(ctx)
	if commitErr != nil {
		return nil, commitErr
	}

	return uRead, nil
}

func Read(
	ctx context.Context,
	conn *pgx.Conn,
	versionKey *security.VersionKey,
	id models.ID,
) (*User, error) {
	var apiSecretEncrypted, displayNameEncrypted, emailEncrypted string
	var u User

	const selectQuery = `
    	select
      		api_secret,
      		api_secret_digest,
      		display_name,
      		display_name_digest,
      		email,
      		email_digest,
      		key_version,
      		org,
      		password,
      		ctime,
      		mtime,
      		role,
      		schema_version,
      		signature,
      		status
    	from users
    	where id = $1
		`

	selectErr := conn.QueryRow(ctx, selectQuery, id).
		Scan(
			&apiSecretEncrypted,
			&u.APISecretDigest,
			&displayNameEncrypted,
			&u.DisplayNameDigest,
			&emailEncrypted,
			&u.EmailDigest,
			&u.KeyVersion,
			&u.Org,
			&u.Password,
			&u.Meta.Ctime,
			&u.Meta.Mtime,
			&u.Meta.Role,
			&u.Meta.SchemaVersion,
			&u.Meta.Signature,
			&u.Meta.Status,
		)
	if selectErr != nil {
		if pgx.ErrNoRows == selectErr {
			return nil, models.ErrNotFound
		}
		return nil, selectErr
	}

	// mismatch schema versions require migration
	if SchemaVersion != u.Meta.SchemaVersion {
		migrated := false
		// put migration code here

		if !migrated {
			return nil, models.ErrModelMigrate
		}
	}

	u.ID = id

	// Decrypt database-encrypted fields.
	u.APISecret = safe.TrustedVarChar(apiSecretEncrypted)
	u.DisplayName = safe.TrustedVarChar(displayNameEncrypted)
	u.Email = safe.TrustedVarChar(emailEncrypted)
	u.encrypted = true // set so Decrypt() sees encrypted state
	decryptErr := u.Decrypt(versionKey)
	if decryptErr != nil {
		return nil, decryptErr
	}

	return &u, nil
}

// Refresh will re-initialize data fields after an update,
// typically inside the same txn that performed the update.
func (u *User) Refresh(ctx context.Context,
	conn *pgx.Conn,
	versionKey *security.VersionKey,
) error {
	uRead, uReadErr := Read(ctx, conn, versionKey, u.ID)
	if uReadErr != nil {
		return uReadErr
	}

	// only fields that can be updated by API or trigger
	// need to be updated
	u.APISecret = uRead.APISecret
	u.APISecretDigest = uRead.APISecretDigest
	u.DisplayName = uRead.DisplayName
	u.DisplayNameDigest = uRead.DisplayNameDigest
	u.Email = uRead.Email
	u.EmailDigest = uRead.EmailDigest
	u.Password = uRead.Password
	u.Meta = uRead.Meta

	return nil
}

// ReEncrypt re-encrypts all encryptable fields with the new key.
// Assumes User is already in the db; updates the relevant fields.
//
// The digests remain the same as they are the digests of
// the unencrypted fields.
func (u *User) ReEncrypt(ctx context.Context,
	conn *pgx.Conn,
	keyVersion uuid.UUID,
	versionKey *security.VersionKey,
) error {
	key, keyErr := versionKey.Get(keyVersion)
	if keyErr != nil {
		return keyErr
	}

	decryptErr := u.Decrypt(versionKey)
	if decryptErr != nil {
		return decryptErr
	}

	encryptErr := u.Encrypt(key, keyVersion)
	if encryptErr != nil {
		return encryptErr
	}

	tx, txErr := conn.Begin(ctx)
	if txErr != nil {
		return txErr
	}
	defer tx.Rollback(ctx) // nolint:errcheck

	const reEncryptQuery = `
		update users set
 			api_secret = $1,
 			display_name = $2,
			email = $3,
			key_version = $4
		where id = $5
		`

	result, err := tx.Conn().Exec(ctx, reEncryptQuery,
		u.APISecret,
		u.DisplayName,
		u.Email,
		keyVersion,
		u.ID,
	)
	if err != nil {
		return err
	}

	updated := result.RowsAffected()
	if updated != 1 {
		return models.ErrRowsAffected
	}

	// KeyVersion is not set in Refresh
	u.KeyVersion = keyVersion

	refreshErr := u.Refresh(ctx, tx.Conn(), versionKey)
	if refreshErr != nil {
		return refreshErr
	}

	auditErr := audit.Insert(ctx, tx.Conn(), audit.UserReEncrypt, "users", u.ID)
	if auditErr != nil {
		return auditErr
	}

	return tx.Commit(ctx)
}

// UpdateAPISecret generates a new API secret on behalf of the user.
func (u *User) UpdateAPISecret(ctx context.Context,
	conn *pgx.Conn,
	versionKey *security.VersionKey,
) error {
	key, keyErr := versionKey.Get(u.KeyVersion)
	if keyErr != nil {
		return keyErr
	}
	newAPISecret := models.NewID().String()
	encryptedNewAPISecret, encryptErr := security.Encrypt(
		newAPISecret,
		key,
	)
	if encryptErr != nil {
		return encryptErr
	}

	newAPISecretDigest := security.EncodedSHA256(newAPISecret)

	tx, txErr := conn.Begin(ctx)
	if txErr != nil {
		return txErr
	}
	defer tx.Rollback(ctx) // nolint:errcheck

	const updateQuery = `update users set api_secret = $1, api_secret_digest = $2 where id = $3`

	result, err := tx.Exec(ctx, updateQuery, encryptedNewAPISecret, newAPISecretDigest, u.ID)
	if err != nil {
		return err
	}

	updated := result.RowsAffected()
	if updated == 0 {
		return pgx.ErrNoRows
	}
	if updated != 1 {
		return models.ErrRowsAffected
	}

	refreshErr := u.Refresh(ctx, tx.Conn(), versionKey)
	if refreshErr != nil {
		return refreshErr
	}

	auditErr := audit.Insert(ctx, tx.Conn(), audit.UserAPISecret, "users", u.ID)
	if auditErr != nil {
		return auditErr
	}

	return tx.Commit(ctx)
}

// UpdateDisplayName changes the user display name and display name digest.
func (u *User) UpdateDisplayName(ctx context.Context,
	conn *pgx.Conn,
	versionKey *security.VersionKey,
	newDisplayName safe.VarChar,
) error {
	key, keyErr := versionKey.Get(u.KeyVersion)
	if keyErr != nil {
		return keyErr
	}

	encryptedNewDisplayName, encryptErr := security.Encrypt(newDisplayName.String(), key)
	if encryptErr != nil {
		return encryptErr
	}

	newDisplayNameDigest := security.EncodedSHA256(newDisplayName.String())

	tx, txErr := conn.Begin(ctx)
	if txErr != nil {
		return txErr
	}
	defer tx.Rollback(ctx) // nolint:errcheck

	const updateQuery = `update users set display_name = $1, display_name_digest = $2 where id = $3`

	result, err := tx.Exec(ctx, updateQuery, encryptedNewDisplayName, newDisplayNameDigest, u.ID)
	if err != nil {
		return err
	}

	updated := result.RowsAffected()
	if updated == 0 {
		return pgx.ErrNoRows
	}
	if updated != 1 {
		return models.ErrRowsAffected
	}

	refreshErr := u.Refresh(ctx, tx.Conn(), versionKey)
	if refreshErr != nil {
		return refreshErr
	}

	auditErr := audit.Insert(ctx, tx.Conn(), audit.UserDisplayName, "users", u.ID)
	if auditErr != nil {
		return auditErr
	}

	return tx.Commit(ctx)
}

// UpdatePassword changes the user password.
// Assumes password is already derived.
func (u *User) UpdatePassword(ctx context.Context,
	conn *pgx.Conn,
	versionKey *security.VersionKey,
	newPassword safe.Password,
) error {
	tx, txErr := conn.Begin(ctx)
	if txErr != nil {
		return txErr
	}
	defer tx.Rollback(ctx) // nolint:errcheck

	passwordUpdateErr := models.Update(context.Background(),
		tx.Conn(),
		"users",
		u.ID,
		"password",
		newPassword)
	if passwordUpdateErr != nil {
		return passwordUpdateErr
	}

	refreshErr := u.Refresh(ctx, tx.Conn(), versionKey)
	if refreshErr != nil {
		return refreshErr
	}

	auditErr := audit.Insert(ctx, tx.Conn(), audit.UserPassword, "users", u.ID)
	if auditErr != nil {
		return auditErr
	}

	return tx.Commit(ctx)
}

// UpdateStatus changes the user status.
func (u *User) UpdateStatus(ctx context.Context,
	conn *pgx.Conn,
	versionKey *security.VersionKey,
	newStatus models.Status,
) error {
	tx, txErr := conn.Begin(ctx)
	if txErr != nil {
		return txErr
	}
	defer tx.Rollback(ctx) // nolint:errcheck

	statusUpdateErr := models.Update(context.Background(),
		tx.Conn(),
		"users",
		u.ID,
		"status",
		newStatus)
	if statusUpdateErr != nil {
		return statusUpdateErr
	}

	refreshErr := u.Refresh(ctx, tx.Conn(), versionKey)
	if refreshErr != nil {
		return refreshErr
	}

	auditErr := audit.Insert(ctx, tx.Conn(), audit.Status, "users", u.ID)
	if auditErr != nil {
		return auditErr
	}

	return tx.Commit(ctx)
}
