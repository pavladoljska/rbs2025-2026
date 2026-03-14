package com.zuehlke.securesoftwaredevelopment.repository;

import com.zuehlke.securesoftwaredevelopment.config.AuditLogger;
import com.zuehlke.securesoftwaredevelopment.domain.Hotel;
import com.zuehlke.securesoftwaredevelopment.domain.RoomType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

@Repository
public class RoomRepository {
    private static final Logger LOG = LoggerFactory.getLogger(RoomRepository.class);
    private static final AuditLogger auditLogger = AuditLogger.getAuditLogger(RoomRepository.class);

    private final DataSource dataSource;

    public RoomRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public List<RoomType> getAllRoomTypes(int hotelId) {
        List<RoomType> roomTypes = new ArrayList<>();
        String query = "SELECT id, name, capacity, pricePerNight, totalRooms FROM roomType WHERE hotelId = " + hotelId;
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(query)) {
            while (rs.next()) {
                Integer id = rs.getInt(1);
                String name = rs.getString(2);
                int capacity = rs.getInt(3);
                BigDecimal pricePerNight = rs.getBigDecimal(4);
                int totalRooms = rs.getInt(5);

                roomTypes.add(new RoomType(id, hotelId, name, capacity, pricePerNight, totalRooms));
            }
        } catch (SQLException e) {
            LOG.error("Failed to get room types for hotelId={}", hotelId, e);
        }

        return roomTypes;
    }

    public RoomType findByIdAndHotelId(int roomTypeId, int hotelId) {
        RoomType roomType = new RoomType();
        String query = "SELECT name, capacity, pricePerNight, totalRooms FROM roomType WHERE roomType.id = " + roomTypeId +
                " and roomType.hotelId = " + hotelId;

        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(query)) {
            if (rs.next()) {
                String name = rs.getString(1);
                int capacity = rs.getInt(2);
                BigDecimal pricePerNight = rs.getBigDecimal(3);
                int totalRooms = rs.getInt(4);

                roomType.setId(roomTypeId);
                roomType.setHotelId(hotelId);
                roomType.setName(name);
                roomType.setCapacity(capacity);
                roomType.setPricePerNight(pricePerNight);
                roomType.setTotalRooms(totalRooms);
                return roomType;
            }
        } catch (SQLException e) {
            LOG.error("Failed to find room type with id={} for hotelId={}", roomTypeId, hotelId, e);
        }

        return null;
    }
}
