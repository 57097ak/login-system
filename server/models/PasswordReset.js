const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const PasswordResetToken = sequelize.define('PasswordResetToken', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  userId: {
    type: DataTypes.UUID,
    allowNull: false,
  },
  token: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  tokenExpiry: {
    type: DataTypes.BIGINT,
    allowNull: false,
  },
}, {
  tableName: 'password_reset_tokens',
  timestamps: false,
});

module.exports = PasswordResetToken;
