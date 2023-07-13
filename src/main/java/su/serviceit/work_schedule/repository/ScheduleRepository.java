package su.serviceit.work_schedule.repository;

import su.serviceit.work_schedule.entity.Schedule;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;

@Repository
public interface ScheduleRepository extends JpaRepository<Schedule, Long> {
    Schedule getScheduleByDate(LocalDate date);
}
