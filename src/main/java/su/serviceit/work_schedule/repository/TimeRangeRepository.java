package su.serviceit.work_schedule.repository;

import su.serviceit.work_schedule.entity.TimeRange;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TimeRangeRepository extends JpaRepository<TimeRange, Long> {
}
