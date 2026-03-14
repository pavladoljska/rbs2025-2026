package com.zuehlke.securesoftwaredevelopment.repository;

import com.zuehlke.securesoftwaredevelopment.domain.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.sql.*;

@Repository
public class UserRepository {

    private static final Logger LOG = LoggerFactory.getLogger(UserRepository.class);

    private final DataSource dataSource;

    public UserRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public User findUser(String username) {
        String query = "SELECT id, username, password FROM users WHERE username='" + username + "'";
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(query)) {
            if (rs.next()) {
                int id = rs.getInt(1);
                String username1 = rs.getString(2);
                String password = rs.getString(3);
                return new User(id, username1, password);
            }
        } catch (SQLException e) {
            LOG.error("Failed to find user by username", e);
        }
        return null;
    }

    public String findUsername(int id) {
        String query = "SELECT username FROM users WHERE id=" + id;
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(query)) {
            if (rs.next()) {
                String username = rs.getString(1);
                return username;
            }
        } catch (SQLException e) {
            LOG.error("Failed to find username for userId={}", id, e);
        }
        return null;
    }

    public void updateUsername(int id, String username) {
        String query = "UPDATE users SET username = ? WHERE id = " + id;

        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(query);
        ) {
            statement.setString(1, username);
            statement.executeUpdate();
        } catch (SQLException e) {
            LOG.error("Failed to update username for userId={}", id, e);
        }
    }

    public boolean validCredentials(String username, String password) {
        String query = "SELECT username FROM users WHERE username='" + username + "' AND password='" + password + "'";
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(query)) {
            return rs.next();
        } catch (SQLException e) {
            LOG.error("Failed to validate credentials for username='{}'", username, e);
        }
        return false;
    }

    public void delete(int userId) {
        String query = "DELETE FROM users WHERE id = " + userId;
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
        ) {
            statement.executeUpdate(query);
        } catch (SQLException e) {
            LOG.error("Failed to delete user with id={}", userId, e);
        }
    }
}
