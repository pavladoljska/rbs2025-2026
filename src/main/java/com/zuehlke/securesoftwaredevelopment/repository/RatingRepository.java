package com.zuehlke.securesoftwaredevelopment.repository;

import com.zuehlke.securesoftwaredevelopment.domain.Rating;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

@Repository
public class RatingRepository {

    private static final Logger LOG = LoggerFactory.getLogger(RatingRepository.class);

    private final DataSource dataSource;

    public RatingRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public void createOrUpdate(Rating rating) {
        String query = "SELECT hotelId, userId, rating FROM ratings WHERE hotelId = " + rating.getHotelId() + " AND userID = " + rating.getUserId();
        String query2 = "update ratings SET rating = ? WHERE hotelId = ? AND userId = ?";
        String query3 = "insert into ratings(hotelId, userId, rating) values (?, ?, ?)";

        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(query)
        ) {
            if (rs.next()) {
                PreparedStatement preparedStatement = connection.prepareStatement(query2);
                preparedStatement.setInt(1, rating.getRating());
                preparedStatement.setInt(2, rating.getHotelId());
                preparedStatement.setInt(3, rating.getUserId());
                preparedStatement.executeUpdate();
            } else {
                PreparedStatement preparedStatement = connection.prepareStatement(query3);
                preparedStatement.setInt(1, rating.getHotelId());
                preparedStatement.setInt(2, rating.getUserId());
                preparedStatement.setInt(3, rating.getRating());
                preparedStatement.executeUpdate();
            }
        } catch (SQLException e) {
            LOG.error("Failed to create/update rating for hotelId={}, userId={}", rating.getHotelId(), rating.getUserId(), e);
        }
    }

    public List<Rating> getAll(String hotelId) {
        List<Rating> ratingList = new ArrayList<>();
        String query = "SELECT hotelId, userId, rating FROM ratings WHERE hotelId = " + hotelId;
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(query)) {
            while (rs.next()) {
                ratingList.add(new Rating(rs.getInt(1), rs.getInt(2), rs.getInt(3)));
            }
        } catch (SQLException e) {
            LOG.error("Failed to get ratings for hotelId={}", hotelId, e);
        }
        return ratingList;
    }
}
